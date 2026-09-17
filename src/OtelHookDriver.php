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
        $this->hook('curl_setopt', pre: function (mixed $obj, array $params): void {
            if ($this->applyingOptions || !($params[0] ?? null) instanceof \CurlHandle) {
                return;
            }

            if (isset($params[1]) && is_int($params[1])) {
                $this->registry->for($params[0])->set($params[1], $params[2] ?? null);
            }
        });

        $this->hook('curl_setopt_array', pre: function (mixed $obj, array $params): void {
            if ($this->applyingOptions || !($params[0] ?? null) instanceof \CurlHandle) {
                return;
            }

            if (isset($params[1]) && is_array($params[1])) {
                /** @var array<int, mixed> $options */
                $options = $params[1];
                $this->registry->for($params[0])->setMany($options);
            }
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
                $capture = $url !== null && $this->recorder()->shouldCapture($url);
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

            curl_setopt($handle, CURLOPT_HEADERFUNCTION, function ($ch, string $line) use ($state, $appCallback): int {
                $state->appendResponseHeader($line);

                // Chain, never replace. Returning anything but the byte count
                // aborts the transfer, so the application's return value wins
                // where it has one.
                if ($appCallback !== null) {
                    return (int) $appCallback($ch, $line);
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
