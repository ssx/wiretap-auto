<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Wiretap;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\InMemorySink;

/**
 * A curl-hook record carries the request headers the server received, so it
 * can be replayed: curl's own (Host, Accept, Authorization from USERPWD, the
 * body's length and type) as well as the application's.
 */
beforeAll(function (): void {
    if (extension_loaded('opentelemetry')) {
        Wiretap::boot(new Recorder(sink: new InMemorySink()));
    }
});

beforeEach(function (): void {
    if (!extension_loaded('opentelemetry')) {
        $this->markTestSkipped('ext-opentelemetry is not installed');
    }

    $this->sink = new InMemorySink();
    $this->url = 'http://127.0.0.1:' . TEST_SERVER_PORT . '/headers';
});

function recordWith(InMemorySink $sink, bool $redact, callable $call): Exchange
{
    $recorder = new Recorder(
        sink: $sink,
        blocklist: new Blocklist(),
        redactor: new Redactor(new RedactionConfig(enabled: $redact)),
    );
    Wiretap::setRecorder($recorder);

    $call();
    $recorder->flush();

    expect($sink->all())->toHaveCount(1);

    return $sink->all()[0];
}

/**
 * @return array<string, string> lower-cased name => value
 */
function headerMap(iterable $headers): array
{
    $map = [];

    foreach ($headers as [$name, $value]) {
        $map[strtolower($name)] = $value;
    }

    ksort($map);

    return $map;
}

it('records the headers the server received from a raw curl call', function (): void {
    $received = null;

    $exchange = recordWith($this->sink, false, function () use (&$received): void {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => 'user:secretpass',
            CURLOPT_COOKIE => 'session=abc123',
            CURLOPT_USERAGENT => 'raw/1.0',
            CURLOPT_POSTFIELDS => 'a=1&b=2',
            CURLOPT_HTTPHEADER => ['X-Trace: t1'],
        ]);
        $received = json_decode((string) curl_exec($ch), true);
    });

    expect(headerMap($exchange->requestHeaders))->toBe(headerMap(array_map(null, array_keys($received), $received)))
        ->and($exchange->context['request_headers'])->toBe('reconstructed');
});

it('records the headers the server received from an unwired Guzzle client', function (): void {
    $received = null;

    $exchange = recordWith($this->sink, false, function () use (&$received): void {
        $response = (new GuzzleHttp\Client())->post($this->url, [
            'auth' => ['user', 'secretpass'],
            'form_params' => ['a' => '1'],
            'headers' => ['X-Trace' => 't2'],
        ]);
        $received = json_decode((string) $response->getBody(), true);
    });

    expect(headerMap($exchange->requestHeaders))->toBe(headerMap(array_map(null, array_keys($received), $received)));
});

it('redacts the rebuilt Authorization and Cookie like any other header', function (): void {
    $exchange = recordWith($this->sink, true, function (): void {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => 'user:secretpass',
            CURLOPT_COOKIE => 'session=abc123',
        ]);
        curl_exec($ch);
    });

    $headers = headerMap($exchange->requestHeaders);

    expect($headers['authorization'])->not->toContain(base64_encode('user:secretpass'))
        ->and($headers['cookie'])->not->toContain('abc123')
        ->and($headers['host'])->toBe('127.0.0.1:' . TEST_SERVER_PORT);
});

it('keeps them in plaintext when redaction is off', function (): void {
    $exchange = recordWith($this->sink, false, function (): void {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => 'user:secretpass',
            CURLOPT_COOKIE => 'session=abc123',
        ]);
        curl_exec($ch);
    });

    expect(headerMap($exchange->requestHeaders))->toMatchArray([
        'authorization' => 'Basic ' . base64_encode('user:secretpass'),
        'cookie' => 'session=abc123',
    ]);
});

it('says the headers were sent when the application asked curl for them', function (): void {
    $exchange = recordWith($this->sink, false, function (): void {
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLINFO_HEADER_OUT => true]);
        curl_exec($ch);
    });

    expect($exchange->context['request_headers'])->toBe('sent')
        ->and(headerMap($exchange->requestHeaders))->toHaveKey('accept');
});
