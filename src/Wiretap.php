<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto;

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Sink\NullSink;

/**
 * The zero-configuration entry point.
 *
 * A static holder is pragmatically necessary here: the hooks fire below any
 * container, in code that cannot be injected into. Everything it holds is
 * replaceable, so a framework integration can hand it a properly wired
 * recorder and the hooks will use that instead.
 */
final class Wiretap
{
    private static ?Recorder $recorder = null;

    private static ?OtelHookDriver $driver = null;

    /**
     * Called automatically from _register.php. Safe to call again.
     */
    public static function boot(?Recorder $recorder = null): ?OtelHookDriver
    {
        if ($recorder !== null) {
            self::$recorder = $recorder;
        }

        // Hooks install once per process and cannot be installed again once
        // the target has executed. Re-booting swaps the recorder the existing
        // hooks resolve; it never registers a second set.
        if (self::$driver?->isRegistered() === true) {
            return self::$driver;
        }

        $driver = new OtelHookDriver(static fn (): Recorder => self::recorder());

        if (!$driver->isAvailable()) {
            // No extension. The package is inert rather than broken, and
            // `doctor` explains why nothing is being captured.
            self::$driver = $driver;

            return $driver;
        }

        $driver->register();
        self::$driver = $driver;

        return $driver;
    }

    public static function recorder(): Recorder
    {
        return self::$recorder ??= self::defaultRecorder();
    }

    public static function setRecorder(Recorder $recorder): void
    {
        self::$recorder = $recorder;
    }

    public static function driver(): ?OtelHookDriver
    {
        return self::$driver;
    }

    public static function isCapturing(): bool
    {
        return self::$driver?->isRegistered() === true && self::recorder()->isEnabled();
    }

    /**
     * Human-readable status, for `wiretap doctor` and for the "why is nothing
     * being recorded" question that otherwise costs an afternoon.
     *
     * @return array<string, string>
     */
    public static function diagnostics(): array
    {
        $recorder = self::recorder();
        $blocklist = $recorder->blocklist();

        $diagnostics = self::$driver?->diagnostics() ?? [
            'extension' => extension_loaded('opentelemetry') ? 'loaded' : 'MISSING',
            'registered' => 'no — boot() has not run',
        ];

        $diagnostics['enabled'] = $recorder->isEnabled() ? 'yes' : 'no';
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

    public static function reset(): void
    {
        self::$recorder = null;
        self::$driver = null;
    }

    /**
     * Sensible defaults for someone who has only run `composer require`.
     *
     * Capture is off unless WIRETAP_ENABLED is truthy. This is a debugging
     * tool that records personal data, and a package that starts recording
     * the moment it is installed would be indefensible.
     */
    private static function defaultRecorder(): Recorder
    {
        $enabled = filter_var(getenv('WIRETAP_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL);

        return new Recorder(
            sink: $enabled ? self::defaultSink() : new NullSink(),
            blocklist: new Blocklist([
                new PresetBlocklistProvider([
                    PresetBlocklistProvider::PAYMENT_GATEWAYS,
                    PresetBlocklistProvider::CLOUD_METADATA,
                ]),
                new EnvBlocklistProvider(),
            ]),
            redactor: new Redactor(new RedactionConfig(
                maxBodyBytes: (int) (getenv('WIRETAP_BODY_LIMIT') ?: 65536),
            )),
            sampler: new Sampler(
                rateBasisPoints: (int) (getenv('WIRETAP_SAMPLE_BP') ?: 10000),
            ),
            enabled: $enabled,
        );
    }

    private static function defaultSink(): ExchangeSink
    {
        $path = getenv('WIRETAP_PATH');

        if (!is_string($path) || $path === '') {
            $path = sys_get_temp_dir() . '/wiretap';
        }

        return new NdjsonFileSink($path);
    }
}
