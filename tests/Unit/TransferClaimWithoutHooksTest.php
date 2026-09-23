<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Wiretap;
use Ssx\Wiretap\TransferClaim;

/**
 * Without the hooks nothing strips the claim, and curl rejects it with a
 * ValueError. So wherever the hooks are not running, the claim must not be
 * honoured, and bridges must send nothing.
 */
it('does not honour the claim when the extension is missing', function (): void {
    if (extension_loaded('opentelemetry')) {
        // -n drops every shared extension, opentelemetry included.
        expect(honouredInFreshProcess([], '-n'))->toBe('no');

        return;
    }

    Wiretap::boot();

    expect(Wiretap::driver()?->isRegistered())->toBeFalse()
        ->and(TransferClaim::isHonoured())->toBeFalse()
        ->and(Wiretap::diagnostics()['transfer_claim'] ?? 'not honoured')->toBe('not honoured');
});

it('does not honour the claim when auto is disabled by environment', function (): void {
    expect(honouredInFreshProcess(['WIRETAP_DISABLE_AUTO' => '1']))->toBe('no');
});
