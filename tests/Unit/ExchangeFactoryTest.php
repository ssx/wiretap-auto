<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Internal\ExchangeFactory;
use Ssx\Wiretap\Auto\Internal\HandleState;
use Ssx\Wiretap\CapturedBody;

function stateWith(array $options): HandleState
{
    $state = new HandleState();
    $state->setMany($options);
    $state->beginTransfer(true);

    return $state;
}

it('prefers the headers libcurl actually sent over the configured ones', function (): void {
    $state = stateWith([
        CURLOPT_URL => 'https://api.example.com/v1',
        CURLOPT_HTTPHEADER => ['X-Configured: yes'],
    ]);

    // libcurl adds Host, Accept and Content-Length of its own, so what was
    // configured is only ever a subset of what was sent.
    $exchange = (new ExchangeFactory())->create($state, [
        'url' => 'https://api.example.com/v1',
        'http_code' => 200,
        'request_header' => "GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nX-Configured: yes\r\nAccept: */*\r\n",
    ], 'body');

    expect($exchange->requestHeaders->first('Host'))->toBe('api.example.com')
        ->and($exchange->requestHeaders->first('Accept'))->toBe('*/*')
        ->and($exchange->requestHeaders->first('X-Configured'))->toBe('yes');
});

it('falls back to configured headers when HEADER_OUT was unavailable', function (): void {
    $state = stateWith([
        CURLOPT_URL => 'https://api.example.com/v1',
        CURLOPT_VERBOSE => true,
        CURLOPT_HTTPHEADER => ['X-Configured: yes'],
    ]);

    $exchange = (new ExchangeFactory())->create($state, ['http_code' => 200], 'body');

    expect($exchange->requestHeaders->first('X-Configured'))->toBe('yes');
});

it('uses the effective url so a redirect chain reports where it ended', function (): void {
    $state = stateWith([CURLOPT_URL => 'https://api.example.com/start']);

    $exchange = (new ExchangeFactory())->create($state, [
        'url' => 'https://api.example.com/finished',
        'http_code' => 200,
    ], 'body');

    expect($exchange->uri)->toBe('https://api.example.com/finished');
});

it('records an omission rather than a fabricated body without RETURNTRANSFER', function (): void {
    $state = stateWith([CURLOPT_URL => 'https://api.example.com/v1']);

    // curl_exec() returns true when the body went to stdout. Forcing
    // RETURNTRANSFER on to make capture easier would change where the
    // application's response goes.
    $exchange = (new ExchangeFactory())->create($state, ['http_code' => 200], true);

    expect($exchange->responseBody->isPresent())->toBeFalse()
        ->and($exchange->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_NOT_RETURNED);
});

it('marks a write-callback response as streaming', function (): void {
    $state = stateWith([
        CURLOPT_URL => 'https://api.example.com/v1',
        CURLOPT_WRITEFUNCTION => static fn ($ch, $data): int => strlen($data),
    ]);

    $exchange = (new ExchangeFactory())->create($state, ['http_code' => 200], true);

    expect($exchange->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_STREAMING);
});

it('keeps the size and hash of a truncated body', function (): void {
    $state = stateWith([CURLOPT_URL => 'https://api.example.com/v1']);
    $big = str_repeat('a', 5000);

    $exchange = (new ExchangeFactory(maxBodyBytes: 100))->create($state, ['http_code' => 200], $big);

    expect(strlen((string) $exchange->responseBody->bytes))->toBe(100)
        ->and($exchange->responseBody->truncated)->toBeTrue()
        ->and($exchange->responseBody->size)->toBe(5000)
        ->and($exchange->responseBody->sha256)->toBe(hash('sha256', $big));
});

it('takes the last header block, which is the response the caller received', function (): void {
    $state = stateWith([CURLOPT_URL => 'https://api.example.com/v1']);

    // A redirect chain emits one block per hop.
    $state->appendResponseHeader("HTTP/1.1 301 Moved\r\nLocation: /next\r\n\r\n");
    $state->appendResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");

    $exchange = (new ExchangeFactory())->create($state, ['http_code' => 200], '{}');

    expect($exchange->responseHeaders->first('Content-Type'))->toBe('application/json')
        ->and($exchange->responseHeaders->has('Location'))->toBeFalse();
});

it('records a transport error', function (): void {
    $state = stateWith([CURLOPT_URL => 'https://nope.invalid/v1']);

    $exchange = (new ExchangeFactory())->create($state, [], false, CURLE_COULDNT_RESOLVE_HOST, 'Could not resolve host');

    expect($exchange->error)->not->toBeNull()
        ->and($exchange->error->errno)->toBe(CURLE_COULDNT_RESOLVE_HOST)
        ->and($exchange->error->message)->toBe('Could not resolve host')
        ->and($exchange->status)->toBeNull()
        ->and($exchange->failed())->toBeTrue();
});

it('converts curl timings from seconds to microseconds', function (): void {
    $state = stateWith([CURLOPT_URL => 'https://api.example.com/v1']);

    $exchange = (new ExchangeFactory())->create($state, [
        'http_code' => 200,
        'namelookup_time' => 0.01,
        'connect_time' => 0.05,
        'starttransfer_time' => 0.25,
        'total_time' => 0.5,
    ], 'body');

    expect($exchange->timings->dns)->toBe(10_000)
        ->and($exchange->timings->connect)->toBe(50_000)
        ->and($exchange->timings->ttfb)->toBe(250_000)
        ->and($exchange->timings->total)->toBe(500_000);
});
