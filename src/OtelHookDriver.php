<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto;

use Ssx\Wiretap\Auto\Internal\ExchangeFactory;
use Ssx\Wiretap\Auto\Internal\HandleRegistry;
use Ssx\Wiretap\Auto\Internal\HandleState;
use Ssx\Wiretap\Contract\HookDriver;
use Ssx\Wiretap\Recorder;

/**
 * Installs curl hooks through ext-opentelemetry.
 *
 * The extension exposes PHP's zend_observer API to userland. Observation of
 * *internal* functions — which is what curl_exec is — arrived in PHP 8.2; on
 * 8.0 and 8.1 the same API sees only userland functions and methods. That is
 * the whole reason wiretap's floor is 8.2.
 *
 * Note that `opentelemetry.allow_stack_extension` is NOT required here. It is
 * only needed to *add* arguments in a pre-hook, and nothing below does that:
 * options are applied by calling curl_setopt() on the handle directly, which
 * is an ordinary function call.
 *
 * Everything in this class is glue. The logic that can be got wrong lives in
 * Internal\HandleState and Internal\ExchangeFactory, which are testable
 * without the extension present.
 */
final class OtelHookDriver implements HookDriver
{
    private const HOOK_FUNCTION = 'OpenTelemetry\Instrumentation\hook';

    private bool $registered = false;

    /**
     * Guards against our own curl_setopt() calls re-entering the setopt hook.
     */
    private bool $applyingOptions = false;

    private readonly HandleRegistry $registry;

    /** @var \Closure(): Recorder */
    private readonly \Closure $resolveRecorder;

    /**
     * The recorder is resolved per call, not captured at construction.
     *
     * Hooks are installed once per process and cannot be installed again once
     * the target function has executed, so a driver holding a fixed Recorder
     * would pin whichever one happened to exist at autoload time. A framework
     * booting afterwards could never swap in its own properly wired recorder,
     * and the hooks would go on writing to a default sink forever.
     *
     * @param Recorder|\Closure(): Recorder $recorder
     */
    public function __construct(
        Recorder|\Closure $recorder,
        private readonly ExchangeFactory $factory = new ExchangeFactory(),
        ?HandleRegistry $registry = null,
    ) {
        $this->resolveRecorder = $recorder instanceof Recorder
            ? static fn (): Recorder => $recorder
            : $recorder;

        $this->registry = $registry ?? new HandleRegistry();
    }

    private function recorder(): Recorder
    {
        return ($this->resolveRecorder)();
    }

    public function isAvailable(): bool
    {
        return extension_loaded('opentelemetry') && function_exists(self::HOOK_FUNCTION);
    }

    public function isRegistered(): bool
    {
        return $this->registered;
    }

    public function register(): void
    {
        if ($this->registered || !$this->isAvailable()) {
            return;
        }

        $this->registered = true;

        $this->hookInit();
        $this->hookSetopt();
        $this->hookLifecycle();
        $this->hookExec();
    }

    private function hookInit(): void
    {
        $this->hook('curl_init', post: function (mixed $obj, array $params, mixed $handle): void {
            if (!$handle instanceof \CurlHandle) {
                return;
            }

            $state = $this->registry->for($handle);

            // curl_init($url) is the one-argument form.
            if (isset($params[0]) && is_string($params[0])) {
                $state->set(CURLOPT_URL, $params[0]);
            }
        });
    }

    private function hookSetopt(): void
    {
        // Both record in post, not pre.
        //
        // Recording before curl had accepted the value meant a rejected option
        // still changed the shadow state. With CURLOPT_HEADER on, a
        // curl_setopt_array() carrying an invalid CURLOPT_HTTPHEADER plus
        // CURLOPT_HEADER => false failed before curl ever disabled headers —
        // but wiretap already believed they were off, so if the application
        // caught the failure and executed anyway, the response headers were
        // recorded as body text with no header redaction applied to them.
        $this->hook('curl_setopt', post: function (mixed $obj, array $params, mixed $result, ?\Throwable $exception = null): void {
            if ($this->applyingOptions || !($params[0] ?? null) instanceof \CurlHandle) {
                return;
            }

            // curl rejected it, so the handle is unchanged and so is our model
            // of it. Nothing to record, and nothing has diverged.
            if ($exception !== null || $result === false) {
                return;
            }

            if (isset($params[1]) && is_int($params[1])) {
                // Recording the option also clears headersInstalled when the
                // application replaces CURLOPT_HEADERFUNCTION, so our wrapper
                // is reinstalled on the next captured transfer rather than
                // leaving the handle with no header capture at all.
                $this->registry->for($params[0])->set($params[1], $params[2] ?? null);
            }
        });

        $this->hook('curl_setopt_array', post: function (mixed $obj, array $params, mixed $result, ?\Throwable $exception = null): void {
            if ($this->applyingOptions || !($params[0] ?? null) instanceof \CurlHandle) {
                return;
            }

            if (!isset($params[1]) || !is_array($params[1])) {
                return;
            }

            /** @var array<int, mixed> $options */
            $options = $params[1];

            if ($exception === null && $result !== false) {
                $this->registry->for($params[0])->setMany($options);

                return;
            }

            // It stopped at the first option curl refused, having already
            // applied the ones before it. There is no way to ask curl which
            // those were, so the shadow state is no longer a model of this
            // handle and every capture decision from it would be a guess.
            $this->registry->for($params[0])->markUnsafe(
                'curl_setopt_array() failed part way through; the applied options are unknown',
            );
        });
    }

    private function hookLifecycle(): void
    {
        $this->hook('curl_copy_handle', post: function (mixed $obj, array $params, mixed $copy): void {
            if (($params[0] ?? null) instanceof \CurlHandle && $copy instanceof \CurlHandle) {
                $this->registry->copy($params[0], $copy);
            }
        });

        $this->hook('curl_reset', pre: function (mixed $obj, array $params): void {
            if (($params[0] ?? null) instanceof \CurlHandle) {
                $this->registry->for($params[0])->reset();
            }
        });

        $this->hook('curl_close', pre: function (mixed $obj, array $params): void {
            if (($params[0] ?? null) instanceof \CurlHandle) {
                $this->registry->forget($params[0]);
            }
        });
    }

    private function hookExec(): void
    {
        $this->hook(
            'curl_exec',
            pre: function (mixed $obj, array $params): void {
                if (!($params[0] ?? null) instanceof \CurlHandle) {
                    return;
                }

                $handle = $params[0];
                $state = $this->registry->for($handle);
                $url = $state->url();

                // The gate runs before the transfer, so a blocked payload is
                // never even asked for.
                //
                // A handle whose options we can no longer model is declined
                // outright: a record built on a guess about CURLOPT_HEADER can
                // put unredacted response headers in the body, and no record
                // is better than a wrong one.
                $capture = $url !== null
                    && !$state->isUnsafe()
                    && $this->recorder()->shouldCapture($url);
                $state->beginTransfer($capture);

                if ($capture) {
                    $this->installCaptureOptions($handle, $state);
                }
            },
            post: function (mixed $obj, array $params, mixed $result): void {
                if (!($params[0] ?? null) instanceof \CurlHandle) {
                    return;
                }

                $handle = $params[0];

                if (!$this->registry->has($handle)) {
                    return;
                }

                $state = $this->registry->for($handle);

                if (!$state->isCapturing()) {
                    return;
                }

                $info = curl_getinfo($handle);
                $errno = curl_errno($handle);

                $this->recorder()->record($this->factory->create(
                    state: $state,
                    info: is_array($info) ? $info : [],
                    result: $result,
                    errno: $errno,
                    error: $errno !== 0 ? curl_error($handle) : '',
                ));
            },
        );
    }

    /**
     * Turn on the two options we need, without taking anything away from the
     * application.
     */
    private function installCaptureOptions(\CurlHandle $handle, HandleState $state): void
    {
        if ($state->headersInstalled()) {
            return;
        }

        $this->applyingOptions = true;

        try {
            // CURLINFO_HEADER_OUT and CURLOPT_VERBOSE share one libcurl debug
            // slot — setting ours would silently blank theirs. If they asked
            // for verbose output, they keep it and we fall back to the
            // shadowed HTTPHEADER lines.
            if ($state->canUseHeaderOut()) {
                curl_setopt($handle, CURLINFO_HEADER_OUT, true);
            }

            $appCallback = $state->appHeaderFunction();
            $appStream = $state->appHeaderStream();

            curl_setopt($handle, CURLOPT_HEADERFUNCTION, function ($ch, string $line) use ($state, $appCallback, $appStream): int {
                $state->appendResponseHeader($line);

                // Chain, never replace. Returning anything but the byte count
                // aborts the transfer, so the application's return value wins
                // where it has one.
                if ($appCallback !== null) {
                    return (int) $appCallback($ch, $line);
                }

                // No callback, but a destination they set with
                // CURLOPT_WRITEHEADER. Our callback has taken that destination
                // over, so we have to honour it ourselves or their file stays
                // empty.
                if ($appStream !== null) {
                    @fwrite($appStream, $line);
                }

                return strlen($line);
            });

            $state->markHeadersInstalled();
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
        } finally {
            $this->applyingOptions = false;
        }
    }

    private function hook(string $function, ?\Closure $pre = null, ?\Closure $post = null): void
    {
        try {
            (self::HOOK_FUNCTION)(null, $function, pre: $pre, post: $post);
        } catch (\Throwable) {
            // A hook that cannot be installed leaves that function
            // uninstrumented. It must not take the application down with it.
        }
    }

    /**
     * @return array<string, string>
     */
    public function diagnostics(): array
    {
        return [
            'extension' => extension_loaded('opentelemetry') ? 'loaded' : 'MISSING',
            'version' => (string) (phpversion('opentelemetry') ?: 'n/a'),
            'hook_api' => function_exists(self::HOOK_FUNCTION) ? 'available' : 'MISSING',
            'registered' => $this->registered ? 'yes' : 'no',
            'live_handles' => (string) $this->registry->count(),
            'php' => PHP_VERSION,
            'curl' => (string) (curl_version()['version'] ?? 'n/a'),
        ];
    }
}
