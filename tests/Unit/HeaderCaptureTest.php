<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Internal\HandleRegistry;
use Ssx\Wiretap\Auto\Internal\HandleState;
use Ssx\Wiretap\Headers;

function feedHeaders(HandleState $state, string ...$lines): void
{
    foreach ($lines as $line) {
        $state->appendResponseHeader($line . "\r\n");
    }

    $state->appendResponseHeader("\r\n");
}

describe('response header blocks', function (): void {
    it('does not let trailers replace the real response headers', function (): void {
        // Blocks were split on blank lines, so a trailer block looked like a
        // fresh response: the real Content-Type was lost, the factory reported
        // none, and core then treated a binary body as capturable and stored
        // it.
        $state = new HandleState();
        $state->beginTransfer(true);

        feedHeaders(
            $state,
            'HTTP/1.1 200 OK',
            'Content-Type: application/octet-stream',
            'Transfer-Encoding: chunked',
            'Trailer: X-End',
        );
        $state->appendResponseHeader("X-End: yes\r\n");

        $headers = Headers::fromRaw($state->finalResponseHeaderBlock());

        expect($headers->first('Content-Type'))->toBe('application/octet-stream')
            ->and($headers->first('X-End'))->toBe('yes');
    });

    it('records the final response of a redirect chain, not an earlier hop', function (): void {
        $state = new HandleState();
        $state->beginTransfer(true);

        feedHeaders($state, 'HTTP/1.1 302 Found', 'Location: /next', 'Set-Cookie: sid=abc');
        feedHeaders($state, 'HTTP/1.1 200 OK', 'Content-Type: application/json');

        expect(Headers::fromRaw($state->finalResponseHeaderBlock())->first('Content-Type'))
            ->toBe('application/json')
            ->and($state->finalResponseHeaderBlock())->not->toContain('Set-Cookie')
            // The hop is still observed, just not recorded as this response's.
            ->and($state->responseHeaders())->toContain('Set-Cookie');
    });

    it('keeps room for the final response however long the redirect chain', function (): void {
        // One shared buffer meant a long chain could exhaust it before the
        // final response started, so its Content-Type was discarded and the
        // redactor kept a body it would otherwise have dropped.
        $state = new HandleState();
        $state->beginTransfer(true);

        for ($i = 0; $i < 60; ++$i) {
            $state->appendResponseHeader("HTTP/1.1 302 Found\r\n");
            $state->appendResponseHeader('X-Pad: ' . str_repeat('a', 60000) . "\r\n");
        }

        $state->appendResponseHeader("HTTP/1.1 200 OK\r\n");
        $state->appendResponseHeader("Content-Type: application/json\r\n");

        expect(Headers::fromRaw($state->finalResponseHeaderBlock())->first('Content-Type'))
            ->toBe('application/json')
            ->and($state->headersTruncated())->toBeTrue();
    });

    it('does not flag truncation for an ordinary response', function (): void {
        $state = new HandleState();
        $state->beginTransfer(true);

        feedHeaders($state, 'HTTP/1.1 200 OK', 'Content-Type: application/json');

        expect($state->headersTruncated())->toBeFalse();
    });

    it('clears the buffers between transfers on a reused handle', function (): void {
        $state = new HandleState();
        $state->beginTransfer(true);
        feedHeaders($state, 'HTTP/1.1 500 Server Error', 'Content-Type: text/plain');

        $state->beginTransfer(true);
        feedHeaders($state, 'HTTP/1.1 200 OK', 'Content-Type: application/json');

        expect($state->responseHeaders())->not->toContain('500')
            ->and(Headers::fromRaw($state->finalResponseHeaderBlock())->first('Content-Type'))
            ->toBe('application/json');
    });
});

describe('registry capacity', function (): void {
    it('declines a new handle rather than forgetting the ones it is instrumenting', function (): void {
        // Clearing the map discarded the state of handles that were still live
        // and still instrumented. Their recorded CURLOPT_HEADERFUNCTION went
        // with it, so the next capture installed a fresh wrapper with nothing
        // to chain onto and the application's own header callback stopped
        // being called.
        $registry = new HandleRegistry(maxHandles: 3);

        $live = [];

        for ($i = 0; $i < 3; ++$i) {
            $handle = curl_init("https://example.test/{$i}");
            $live[] = $handle;
            $registry->track($handle)->set(CURLOPT_HEADERFUNCTION, static fn ($ch, string $l): int => strlen($l));
        }

        $overflow = curl_init('https://example.test/overflow');
        $state = $registry->track($overflow);

        expect($state->isUnsafe())->toBeTrue()
            ->and($registry->has($overflow))->toBeFalse()
            ->and($registry->count())->toBe(3)
            ->and($registry->track($live[0])->hasAppHeaderFunction())->toBeTrue();
    });

    it('takes new handles again once the application has finished with others', function (): void {
        $registry = new HandleRegistry(maxHandles: 2);

        $first = curl_init('https://example.test/1');
        $second = curl_init('https://example.test/2');
        $registry->track($first);
        $registry->track($second);

        expect($registry->track(curl_init('https://example.test/3'))->isUnsafe())->toBeTrue();

        unset($first, $second);
        gc_collect_cycles();

        expect($registry->track(curl_init('https://example.test/4'))->isUnsafe())->toBeFalse();
    });

    it('declines a copy at capacity instead of evicting', function (): void {
        $registry = new HandleRegistry(maxHandles: 1);

        $source = curl_init('https://example.test/source');
        $registry->track($source)->set(CURLOPT_HEADERFUNCTION, static fn ($ch, string $l): int => strlen($l));

        $copy = curl_init('https://example.test/copy');
        $registry->copy($source, $copy);

        expect($registry->has($copy))->toBeFalse()
            ->and($registry->track($source)->hasAppHeaderFunction())->toBeTrue();
    });
});
