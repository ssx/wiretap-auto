<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Internal\HandleState;

describe('curl boolean normalisation', function (): void {
    // These expectations were taken from ext-curl itself rather than assumed:
    // CURLOPT_HEADER and CURLOPT_VERBOSE were driven with each of these values
    // against a local server, and the option was on for exactly the values
    // marked on here. PHP casts to int and libcurl treats non-zero as on, so
    // 'yes' is off and 2 is on.
    it('matches what curl actually does with a value', function (mixed $value, bool $expected): void {
        expect(HandleState::curlBool($value))->toBe($expected);
    })->with([
        'true' => [true, true],
        'one' => [1, true],
        'string one' => ['1', true],
        'two' => [2, true],
        'string two' => ['2', true],
        'float one' => [1.0, true],
        'zero' => [0, false],
        'false' => [false, false],
        'string zero' => ['0', false],
        'non-numeric string' => ['yes', false],
        'null' => [null, false],
        'array' => [[], false],
    ]);

    it('sees CURLOPT_HEADER set to a truthy value other than 1', function (): void {
        // Recognising only true, 1 and '1' meant `CURLOPT_HEADER => 2` looked
        // off. With RETURNTRANSFER the response headers were then recorded as
        // body text, where header redaction never looks, and an intermediate
        // redirect's Set-Cookie survived into the record.
        $state = new HandleState();
        $state->set(CURLOPT_HEADER, 2);

        expect($state->returnsHeadersInBody())->toBeTrue();
    });

    it('sees CURLOPT_RETURNTRANSFER set as an integer', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_RETURNTRANSFER, 1);

        expect($state->returnsTransfer())->toBeTrue();
    });

    it('leaves CURLINFO_HEADER_OUT alone when verbose is on as an integer', function (): void {
        // The two share one libcurl debug slot. A strict !== true check read
        // `CURLOPT_VERBOSE => 1` as off, so wiretap claimed the slot and the
        // application's verbose output silently stopped — diagnostics it had
        // explicitly asked for.
        $state = new HandleState();
        $state->set(CURLOPT_VERBOSE, 1);

        expect($state->canUseHeaderOut())->toBeFalse();
    });

    it('still uses CURLINFO_HEADER_OUT when verbose is off', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_VERBOSE, 0);

        expect($state->canUseHeaderOut())->toBeTrue();
    });
});

describe('the application header destination', function (): void {
    it('reports a stream set with CURLOPT_WRITEHEADER and no callback', function (): void {
        // An application can route headers to a file without ever setting a
        // callback. Installing our own HEADERFUNCTION takes that destination
        // over, and the file it was writing to stayed empty.
        $stream = fopen('php://memory', 'r+b');

        $state = new HandleState();
        $state->set(CURLOPT_WRITEHEADER, $stream);

        expect($state->appHeaderStream())->toBe($stream);

        fclose($stream);
    });

    it('reports no stream when the application set its own callback', function (): void {
        // A callback wins over WRITEHEADER in curl, so there is no destination
        // for us to stand in for — chaining onto the callback is enough.
        $stream = fopen('php://memory', 'r+b');

        $state = new HandleState();
        $state->set(CURLOPT_WRITEHEADER, $stream);
        $state->set(CURLOPT_HEADERFUNCTION, static fn ($ch, string $line): int => strlen($line));

        expect($state->appHeaderStream())->toBeNull();

        fclose($stream);
    });

    it('reports no stream when nothing was set', function (): void {
        expect((new HandleState())->appHeaderStream())->toBeNull();
    });
});
