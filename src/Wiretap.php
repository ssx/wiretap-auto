<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto;

use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Wiretap as Core;

/**
 * Registers the hooks, and nothing else.
 *
 * This class used to keep its own static Recorder. That was a mistake: two
 * global holders means a framework can wire up a properly configured recorder,
 * set it on one, and have the hooks go on writing to the other. The recorder
 * now lives in Ssx\Wiretap\Wiretap and this delegates to it, so there is
 * exactly one.
 *
 * The recorder-related methods are kept as pass-throughs rather than removed,
 * because they are the documented way to configure this package and breaking
 * them would gain nothing.
 */
final class Wiretap
{
    private static ?OtelHookDriver $driver = null;

    /**
     * Called automatically from _register.php. Safe to call again.
     */
    public static function boot(?Recorder $recorder = null): ?OtelHookDriver
    {
        if ($recorder !== null) {
            Core::setRecorder($recorder);
        }

        // Hooks install once per process and cannot be installed again once
        // the target has executed. Re-booting swaps the recorder the existing
        // hooks resolve; it never registers a second set.
        if (self::$driver?->isRegistered() === true) {
            return self::$driver;
        }

        $driver = new OtelHookDriver(static fn (): Recorder => Core::recorder());

        if ($driver->isAvailable()) {
            $driver->register();
        }

        return self::$driver = $driver;
    }

    public static function recorder(): Recorder
    {
        return Core::recorder();
    }

    public static function setRecorder(Recorder $recorder): void
    {
        Core::setRecorder($recorder);
    }

    public static function driver(): ?OtelHookDriver
    {
        return self::$driver;
    }

    public static function isCapturing(): bool
    {
        return self::$driver?->isRegistered() === true && Core::recorder()->isEnabled();
    }

    /**
     * Human-readable status, for the "why is nothing being recorded" question
     * that otherwise costs an afternoon.
     *
     * @return array<string, string>
     */
    public static function diagnostics(): array
    {
        $recorder = Core::recorder();
        $blocklist = $recorder->blocklist();

        $diagnostics = self::$driver?->diagnostics() ?? [
            'extension' => extension_loaded('opentelemetry') ? 'loaded' : 'MISSING',
            'registered' => 'no — boot() has not run',
        ];

        $diagnostics['enabled'] = $recorder->isEnabled() ? 'yes' : 'no';

        // Stated in diagnostics, not only in the README. Someone debugging an
        // async call that never appears should be told why in the first place
        // they look.
        $diagnostics['curl_exec (sync)'] = 'captured';
        $diagnostics['curl_multi_* (async)'] = 'captured — async Guzzle, pools '
            . 'and Symfony HttpClient go through the multi interface';
        $diagnostics['blocklist_patterns'] = (string) count($blocklist->patterns());
        $diagnostics['blocklist_failed_closed'] = $blocklist->hasFailedClosed() ? 'YES — blocking everything' : 'no';

        foreach ($blocklist->sources() as $name => $count) {
            $diagnostics['blocklist:' . $name] = $count < 0 ? 'ERROR' : $count . ' patterns';
        }

        foreach ($blocklist->errors() as $i => $error) {
            $diagnostics['blocklist_error_' . $i] = $error;
        }

        return $diagnostics;
    }

    /**
     * Clears the hook driver reference. The hooks themselves cannot be
     * uninstalled — they are process-wide — so this is for tests that need a
     * fresh driver, not a way to stop capturing. Use the recorder for that.
     */
    public static function reset(): void
    {
        self::$driver = null;
        Core::reset();
    }
}
