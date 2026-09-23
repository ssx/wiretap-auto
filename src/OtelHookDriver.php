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
        $this->hookMulti();
    }

    private function hookInit(): void
    {
        $this->hook('curl_init', post: function (mixed $obj, array $params, mixed $handle): void {
            if (!$handle instanceof \CurlHandle) {
                return;
            }

            $state = $this->registry->track($handle);

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

        // After a reset the handle's options are the defaults, so a handle we
        // were not tracking becomes one we can.
        $this->hook('curl_reset', pre: function (mixed $obj, array $params): void {
            if (($params[0] ?? null) instanceof \CurlHandle) {
                $this->registry->track($params[0])->reset();
            }
        });

        // curl_close() is deliberately not hooked. Since PHP 8 it does
        // nothing: the handle stays usable with every option intact, and
        // forgetting its state there made the next transfer look like a blank
        // handle — CURLOPT_HEADER off, so headers recorded inside the body.
        // The WeakMap drops the state when the handle is actually destroyed.
    }

    private function hookExec(): void
    {
        $this->hook(
            'curl_exec',
            pre: function (mixed $obj, array $params): void {
                if (!($params[0] ?? null) instanceof \CurlHandle) {
                    return;
                }

                $this->beginTransfer($params[0]);
            },
            post: function (mixed $obj, array $params, mixed $result): void {
                if (!($params[0] ?? null) instanceof \CurlHandle) {
                    return;
                }

                $handle = $params[0];

                if (!$this->registry->has($handle)) {
                    return;
                }

                $this->finishTransfer($handle, $result);
            },
        );
    }

    /**
     * Decide whether to capture this transfer and prepare the handle.
     *
     * Shared by curl_exec and curl_multi_add_handle: the decision and the
     * options needed to honour it are identical, and only the moment differs.
     */
    private function beginTransfer(mixed $handle): void
    {
        if (!$handle instanceof \CurlHandle) {
            return;
        }

        $state = $this->registry->for($handle);
        $url = $state->url();

        // The gate runs before the transfer, so a blocked payload is never
        // even asked for.
        //
        // A handle whose options we can no longer model is declined outright:
        // a record built on a guess about CURLOPT_HEADER can put unredacted
        // response headers in the body, and no record is better than a wrong
        // one.
        $capture = $url !== null
            && !$state->isUnsafe()
            && $this->recorder()->shouldCapture($url);

        // Without our header wrapper there is no Content-Type to gate the body
        // on and no headers to record, so a transfer we cannot wrap is one we
        // cannot record truthfully. It is declined, and the handle is left
        // exactly as the application configured it.
        if ($capture) {
            $capture = $this->installCaptureOptions($handle, $state);
        }

        $state->beginTransfer($capture);
    }

    /**
     * Record a finished transfer, if it was one we were capturing.
     */
    private function finishTransfer(mixed $handle, mixed $result): void
    {
        if (!$handle instanceof \CurlHandle || !$this->registry->has($handle)) {
            return;
        }

        $state = $this->registry->for($handle);

        if (!$state->isCapturing()) {
            return;
        }

        // Once, however the transfer ends. A multi handle can reach both
        // curl_multi_info_read and curl_multi_remove_handle, and an
        // application is free to call neither, one, or both.
        $state->endTransfer();

        $info = curl_getinfo($handle);
        $errno = curl_errno($handle);

        $this->recorder()->record($this->factory->create(
            state: $state,
            info: is_array($info) ? $info : [],
            result: $result,
            errno: $errno,
            error: $errno !== 0 ? curl_error($handle) : '',
        ));
    }

    /**
     * The multi interface.
     *
     * curl_exec is only half of ext-curl. Guzzle's default handler is
     * Proxy::wrapSync(CurlMultiHandler, CurlHandler), so every async request,
     * every Pool and every concurrent batch goes through curl_multi_* and
     * never touches curl_exec — and Symfony's CurlHttpClient is multi-only, so
     * none of its traffic did either. Vendor code making async calls is
     * precisely what this package exists to see, so this was the gap that
     * mattered most.
     *
     * The shape is the same as the synchronous path, just spread out in time:
     * add_handle is where curl_exec's pre would have run, and completion is
     * reported by info_read or by remove_handle, whichever the application
     * uses. Both are hooked, and finishTransfer() is idempotent per transfer.
     */
    private function hookMulti(): void
    {
        $this->hook('curl_multi_add_handle', post: function (mixed $obj, array $params, mixed $result): void {
            // Only when curl accepted the handle into the multi stack.
            if ($result !== 0) {
                return;
            }

            $this->beginTransfer($params[1] ?? null);
        });

        // The application asking which transfers finished is the earliest
        // reliable completion signal, and the one Guzzle's CurlMultiHandler
        // uses. curl_getinfo is still valid at this point.
        $this->hook('curl_multi_info_read', post: function (mixed $obj, array $params, mixed $result): void {
            if (!is_array($result) || ($result['msg'] ?? null) !== CURLMSG_DONE) {
                return;
            }

            $handle = $result['handle'] ?? null;

            if (!$handle instanceof \CurlHandle) {
                return;
            }

            $this->finishTransfer($handle, $this->multiContent($handle));
        });

        // The backstop, for an application that never calls info_read. Runs
        // before the handle leaves the stack, while its info is still readable.
        $this->hook('curl_multi_remove_handle', pre: function (mixed $obj, array $params): void {
            $handle = $params[1] ?? null;

            if (!$handle instanceof \CurlHandle) {
                return;
            }

            $this->finishTransfer($handle, $this->multiContent($handle));
        });
    }

    /**
     * The response body of a multi transfer.
     *
     * curl_multi_getcontent returns it only when the handle was configured
     * with RETURNTRANSFER; otherwise the body went straight to output or to a
     * file and there is nothing for us to read, which the factory already
     * records as an omission rather than an empty body.
     */
    private function multiContent(\CurlHandle $handle): mixed
    {
        $content = curl_multi_getcontent($handle);

        return $content ?? false;
    }

    /**
     * Install our header callback, without taking anything away from the
     * application. Returns whether header capture is in place.
     *
     * CURLINFO_HEADER_OUT is deliberately not turned on. It would give us the
     * exact request headers, but it gives them to the application too:
     * curl_getinfo() then carries them in plaintext, Authorization included,
     * and Guzzle copies that into handler stats and exception context, from
     * where it reaches logs and error trackers. It also shares libcurl's
     * debug slot with CURLOPT_VERBOSE, so verbose output an application
     * turned on after our first capture never appeared. The record uses the
     * headers the application configured instead, and says so.
     */
    private function installCaptureOptions(\CurlHandle $handle, HandleState $state): bool
    {
        if ($state->headersInstalled()) {
            return true;
        }

        $appCallback = null;

        if ($state->hasAppHeaderFunction()) {
            $appCallback = $state->appHeaderFunction();

            // curl checked this callback from the application's scope, where
            // a private or protected method is perfectly callable. From ours
            // it is not, and a wrapper that cannot call it would silently
            // stop the application's own callback from running.
            if (!self::callableFromHere($appCallback)) {
                return false;
            }
        }

        $this->applyingOptions = true;

        try {
            $appStream = $state->appHeaderStream();
            $registry = $this->registry;

            // Static, and holding neither the state nor the handle: this
            // closure lives on the handle, and curl_copy_handle() gives the
            // copy the same one. The handle curl passes in says whose
            // transfer the line belongs to.
            curl_setopt($handle, CURLOPT_HEADERFUNCTION, static function ($ch, string $line) use ($registry, $appCallback, $appStream): int {
                if ($ch instanceof \CurlHandle && $registry->has($ch)) {
                    $current = $registry->for($ch);

                    if ($current->isCapturing()) {
                        $current->appendResponseHeader($line);
                    }
                }

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

            return true;
        } catch (\Throwable) {
            // Instrumentation must never change application behaviour.
            return false;
        } finally {
            $this->applyingOptions = false;
        }
    }

    /**
     * Whether calling this from our scope reaches what curl would call.
     *
     * is_callable() is not enough on its own. A private method on a class
     * with a public __call passes it, because from outside the class the
     * call is routed to __call — which is not the method the application
     * gave curl, and whose return value aborted the transfer. A method that
     * exists has to be public for us to call it; one that does not exist
     * reaches the magic method from the application's scope too.
     */
    private static function callableFromHere(mixed $callback): bool
    {
        if (!is_callable($callback)) {
            return false;
        }

        if (is_string($callback) && str_contains($callback, '::')) {
            $callback = explode('::', $callback, 2);
        }

        if (is_array($callback) && (is_object($callback[0]) || is_string($callback[0])) && is_string($callback[1])) {
            if (!method_exists($callback[0], $callback[1])) {
                return true;
            }

            try {
                return (new \ReflectionMethod($callback[0], $callback[1]))->isPublic();
            } catch (\ReflectionException) {
                return false;
            }
        }

        return true;
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
