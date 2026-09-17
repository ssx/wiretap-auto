<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Internal\HandleState;

describe('method switches', function (): void {
    it('clears NOBODY when the handle is switched back to GET', function (): void {
        // CURLOPT_HTTPGET clears NOBODY in curl. Keeping it meant a handle
        // that had been used for HEAD reported HEAD for the GET that followed
        // — and a HEAD record carries no response body, so the body of that
        // GET was reported as absent rather than captured.
        $state = new HandleState();
        $state->set(CURLOPT_NOBODY, true);

        expect($state->method())->toBe('HEAD');

        $state->set(CURLOPT_HTTPGET, true);

        expect($state->method())->toBe('GET');
    });

    it('lets NOBODY override an earlier POST', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_POST, true);
        $state->set(CURLOPT_NOBODY, true);

        expect($state->method())->toBe('HEAD');
    });

    it('ignores a switch value curl would treat as off', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_NOBODY, true);
        $state->set(CURLOPT_HTTPGET, 'yes');

        expect($state->method())->toBe('HEAD');
    });
});

describe('request content type', function (): void {
    it('infers form encoding for string POSTFIELDS', function (): void {
        // Reporting null made the redactor try to parse it as JSON, and with
        // bodyPaths configured that failed to inspect the body and dropped the
        // whole thing — so a form post that could have been recorded with one
        // field redacted was recorded as nothing at all.
        $state = new HandleState();
        $state->set(CURLOPT_POSTFIELDS, 'password=secret&a=1');

        expect($state->requestContentType())->toBe('application/x-www-form-urlencoded');
    });

    it('lets an explicit Content-Type header win', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_POSTFIELDS, '{"a":1}');
        $state->set(CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

        expect($state->requestContentType())->toBe('application/json');
    });

    it('reports nothing when there is no body', function (): void {
        expect((new HandleState())->requestContentType())->toBeNull();
    });
});

describe('unsafe shadow state', function (): void {
    it('starts safe', function (): void {
        expect((new HandleState())->isUnsafe())->toBeFalse();
    });

    it('can be marked unsafe with a reason', function (): void {
        $state = new HandleState();
        $state->markUnsafe('curl_setopt_array() failed part way through');

        expect($state->isUnsafe())->toBeTrue()
            ->and($state->unsafeReason())->toContain('part way through');
    });

    it('becomes safe again after a reset', function (): void {
        // curl_reset puts the handle back to defaults, which is the one thing
        // that can make a divergent shadow state agree with it again.
        $state = new HandleState();
        $state->markUnsafe('anything');
        $state->reset();

        expect($state->isUnsafe())->toBeFalse()
            ->and($state->unsafeReason())->toBeNull();
    });
});
