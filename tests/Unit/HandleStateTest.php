<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Internal\HandleRegistry;
use Ssx\Wiretap\Auto\Internal\HandleState;

describe('method inference', function (): void {
    it('infers the method from the options actually set', function (array $options, string $expected): void {
        $state = new HandleState();
        $state->setMany($options);

        expect($state->method())->toBe($expected);
    })->with([
        'default'        => [[], 'GET'],
        'post flag'      => [[CURLOPT_POST => true], 'POST'],
        'postfields'     => [[CURLOPT_POSTFIELDS => 'a=1'], 'POST'],
        'custom request' => [[CURLOPT_CUSTOMREQUEST => 'patch'], 'PATCH'],
        'nobody is HEAD' => [[CURLOPT_NOBODY => true], 'HEAD'],
    ]);

    it('lets CUSTOMREQUEST win over an inferred POST', function (): void {
        $state = new HandleState();
        $state->setMany([CURLOPT_POST => true, CURLOPT_CUSTOMREQUEST => 'DELETE']);

        expect($state->method())->toBe('DELETE');
    });
});

describe('request body reconstruction', function (): void {
    it('returns a string body as-is', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_POSTFIELDS, '{"a":1}');

        expect($state->requestBody())->toBe('{"a":1}')
            ->and($state->requestBodyIsUnreconstructible())->toBeFalse();
    });

    it('encodes an array body', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_POSTFIELDS, ['a' => 1, 'b' => 2]);

        expect($state->requestBody())->toBe('a=1&b=2');
    });

    it('refuses to guess at a file upload', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_POSTFIELDS, ['file' => new CURLFile(__FILE__)]);

        // What was configured is not what was transmitted. Admitting that is
        // better than inventing a body.
        expect($state->requestBody())->toBeNull()
            ->and($state->requestBodyIsUnreconstructible())->toBeTrue();
    });

    it('refuses to guess when a read callback is in use', function (): void {
        $state = new HandleState();
        $state->set(CURLOPT_READFUNCTION, static fn () => '');

        expect($state->requestBodyIsUnreconstructible())->toBeTrue();
    });
});

describe('the HEADER_OUT and VERBOSE conflict', function (): void {
    it('allows HEADER_OUT when the application did not ask for verbose', function (): void {
        expect((new HandleState())->canUseHeaderOut())->toBeTrue();
    });

    it('stands down when the application set VERBOSE', function (): void {
        // The two share one libcurl debug slot: setting ours silently blanks
        // theirs, with no warning. Their output is theirs.
        $state = new HandleState();
        $state->set(CURLOPT_VERBOSE, true);

        expect($state->canUseHeaderOut())->toBeFalse();
    });
});

describe('header callback chaining', function (): void {
    it('remembers the application callback so ours can chain onto it', function (): void {
        $state = new HandleState();
        $callback = static fn ($ch, string $line): int => strlen($line);
        $state->set(CURLOPT_HEADERFUNCTION, $callback);

        expect($state->appHeaderFunction())->toBe($callback);
    });

    it('bounds the response header buffer', function (): void {
        $state = new HandleState();

        for ($i = 0; $i < 2000; ++$i) {
            $state->appendResponseHeader(str_repeat('x', 100));
        }

        expect(strlen($state->responseHeaders()))->toBeLessThan(100_000);
    });
});

describe('handle lifecycle', function (): void {
    it('copies options when a handle is duplicated', function (): void {
        $original = new HandleState();
        $original->set(CURLOPT_URL, 'https://api.example.com/v1');

        $copy = $original->copy();
        $copy->set(CURLOPT_URL, 'https://other.example.com/v1');

        expect($original->url())->toBe('https://api.example.com/v1')
            ->and($copy->url())->toBe('https://other.example.com/v1');
    });

    it('clears everything on reset', function (): void {
        $state = new HandleState();
        $state->setMany([CURLOPT_URL => 'https://api.example.com', CURLOPT_POST => true]);
        $state->reset();

        expect($state->url())->toBeNull()
            ->and($state->method())->toBe('GET');
    });
});

describe('the registry', function (): void {
    it('keeps state per handle', function (): void {
        $registry = new HandleRegistry();
        $a = new stdClass();
        $b = new stdClass();

        $registry->for($a)->set(CURLOPT_URL, 'https://a.example.com');
        $registry->for($b)->set(CURLOPT_URL, 'https://b.example.com');

        expect($registry->for($a)->url())->toBe('https://a.example.com')
            ->and($registry->for($b)->url())->toBe('https://b.example.com')
            ->and($registry->count())->toBe(2);
    });

    it('forgets a closed handle', function (): void {
        $registry = new HandleRegistry();
        $handle = new stdClass();

        $registry->for($handle);
        $registry->forget($handle);

        expect($registry->has($handle))->toBeFalse()
            ->and($registry->count())->toBe(0);
    });

    it('duplicates state for a copied handle', function (): void {
        $registry = new HandleRegistry();
        $from = new stdClass();
        $to = new stdClass();

        $registry->for($from)->set(CURLOPT_URL, 'https://api.example.com');
        $registry->copy($from, $to);

        expect($registry->for($to)->url())->toBe('https://api.example.com');
    });

    it('does not grow without bound when handles leak', function (): void {
        // A worker that never closes its handles must not turn into a memory
        // leak in the instrumentation as well.
        $registry = new HandleRegistry(maxHandles: 10);

        for ($i = 0; $i < 50; ++$i) {
            $registry->for(new stdClass());
        }

        expect($registry->count())->toBeLessThanOrEqual(10);
    });
});
