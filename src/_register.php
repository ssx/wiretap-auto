<?php

declare(strict_types=1);

/**
 * Auto-registration, run by Composer's autoloader.
 *
 * This is the whole install. There is no service provider to add, no
 * bootstrap line to remember, and no SPI to implement — which is the entire
 * point of the package.
 *
 * It bails quietly when the extension is absent so that requiring this in a
 * project that has not installed ext-opentelemetry is inert rather than fatal.
 */

use Ssx\Wiretap\Auto\Wiretap;

(static function (): void {
    if (!extension_loaded('opentelemetry')) {
        return;
    }

    if (!function_exists('OpenTelemetry\Instrumentation\hook')) {
        return;
    }

    // An explicit opt-out, for a process that must not be instrumented at all
    // — an exporter shipping records over HTTP, for instance.
    if (filter_var(getenv('WIRETAP_DISABLE_AUTO') ?: 'false', FILTER_VALIDATE_BOOL)) {
        return;
    }

    try {
        Wiretap::boot();
    } catch (\Throwable) {
        // Registration failing must never prevent an application booting.
    }
})();
