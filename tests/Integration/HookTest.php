<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\OtelHookDriver;
use Ssx\Wiretap\Auto\Wiretap;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;

/**
 * These exercise the real hooks against a real local server.
 *
 * Hooks are process-wide and cannot be uninstalled, so the driver is
 * registered once and the recorder swapped per test.
 */
beforeAll(function (): void {
    if (!extension_loaded('opentelemetry')) {
        return;
    }

    Wiretap::boot(new Recorder(sink: new InMemorySink()));
});

beforeEach(function (): void {
    if (!extension_loaded('opentelemetry')) {
        $this->markTestSkipped('ext-opentelemetry is not installed');
    }

    $this->sink = new InMemorySink();
});

/**
 * Swap in a recorder for this test, reusing the already-registered hooks.
 */
function useRecorder(InMemorySink $sink, ?Blocklist $blocklist = null): Recorder
{
    $recorder = new Recorder(sink: $sink, blocklist: $blocklist ?? new Blocklist());
    Wiretap::setRecorder($recorder);
    Wiretap::boot($recorder);

    return $recorder;
}

it('reports the extension as available', function (): void {
    $driver = new OtelHookDriver(new Recorder(sink: new InMemorySink()));

    expect($driver->isAvailable())->toBeTrue()
        ->and($driver->diagnostics()['extension'])->toBe('loaded');
});

it('captures a raw curl_exec with no application changes', function (): void {
    $recorder = useRecorder($this->sink);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'http://127.0.0.1:' . TEST_SERVER_PORT . '/echo',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => '{"hello":"world"}',
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $body = curl_exec($ch);
    curl_close($ch);
    $recorder->flush();

    expect($body)->toBeString()
        ->and($this->sink->all())->toHaveCount(1);

    $exchange = $this->sink->all()[0];

    expect($exchange->method)->toBe('POST')
        ->and($exchange->status)->toBe(200)
        ->and($exchange->requestBody->bytes)->toBe('{"hello":"world"}')
        ->and($exchange->responseBody->isPresent())->toBeTrue()
        ->and($exchange->requestHeaders->has('Host'))->toBeTrue()
        ->and($exchange->responseHeaders->has('Content-Type'))->toBeTrue()
        ->and($exchange->timings->total)->toBeGreaterThan(0);
});

it('captures a Guzzle client with no middleware attached', function (): void {
    $recorder = useRecorder($this->sink);

    // The point of the whole package: this client is untouched.
    (new GuzzleHttp\Client())->get('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo', [
        'http_errors' => false,
    ]);
    $recorder->flush();

    expect($this->sink->all())->toHaveCount(1)
        ->and($this->sink->all()[0]->uri)->toContain('/echo');
});

it('records nothing for a blocked host but still performs the request', function (): void {
    $recorder = useRecorder(
        $this->sink,
        new Blocklist([new ArrayBlocklistProvider(['127.0.0.1'])]),
    );

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    curl_close($ch);
    $recorder->flush();

    // Blocking capture must never block traffic.
    expect($body)->toBeString()
        ->and($body)->not->toBeEmpty()
        ->and($this->sink->all())->toBeEmpty();
});

it('does not replace an application header callback', function (): void {
    $recorder = useRecorder($this->sink);
    $seen = [];

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, string $line) use (&$seen): int {
        $seen[] = $line;

        return strlen($line);
    });
    curl_exec($ch);
    curl_close($ch);
    $recorder->flush();

    // Both the application's callback and ours must have run.
    expect($seen)->not->toBeEmpty()
        ->and($this->sink->all()[0]->responseHeaders->count())->toBeGreaterThan(0);
});

it('leaves the application response untouched', function (): void {
    $recorder = useRecorder($this->sink);

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    curl_close($ch);

    expect(json_decode((string) $body, true))->toHaveKey('method');
});

it('records a transport failure with the curl errno', function (): void {
    $recorder = useRecorder($this->sink);

    $ch = curl_init('http://127.0.0.1:1/nothing-listening');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    curl_exec($ch);
    curl_close($ch);
    $recorder->flush();

    expect($this->sink->all())->toHaveCount(1)
        ->and($this->sink->all()[0]->error)->not->toBeNull()
        ->and($this->sink->all()[0]->error->errno)->toBeGreaterThan(0);
});

it('tracks options set on a copied handle independently', function (): void {
    $recorder = useRecorder($this->sink);

    $original = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($original, CURLOPT_RETURNTRANSFER, true);

    $copy = curl_copy_handle($original);
    curl_setopt($copy, CURLOPT_URL, 'http://127.0.0.1:' . TEST_SERVER_PORT . '/other');

    curl_exec($original);
    curl_exec($copy);
    curl_close($original);
    curl_close($copy);
    $recorder->flush();

    $uris = array_map(static fn ($e) => $e->uri, $this->sink->all());

    expect($uris)->toHaveCount(2)
        ->and(implode(' ', $uris))->toContain('/echo')
        ->and(implode(' ', $uris))->toContain('/other');
});
