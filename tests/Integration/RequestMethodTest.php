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
 * The method, body and content type on record, checked against what the
 * server received for the same options set in the same order.
 *
 * libcurl keeps one method state that every method option moves: POST=false
 * means GET, NOBODY 1 then 0 means GET, UPLOAD means PUT, and a string
 * POSTFIELDS survives a switch to GET to be sent again by a later POST=true.
 * Modelling each option on its own recorded a POST the server saw as a GET.
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
});

/**
 * @param list<array{int, mixed}|string> $steps options in the order set; 'upload' sets UPLOAD with a 3-byte INFILE
 *
 * @return array{Exchange, array{method: string, body: string, content_type: ?string}}
 */
function sentAndRecorded(array $steps, bool $redact = false, array $bodyPaths = [], array $capturable = RedactionConfig::DEFAULT_CAPTURABLE_TYPES): array
{
    $sink = new InMemorySink();
    $recorder = new Recorder(
        sink: $sink,
        blocklist: new Blocklist(),
        redactor: new Redactor(new RedactionConfig(enabled: $redact, bodyPaths: $bodyPaths, capturableTypes: $capturable)),
    );
    Wiretap::setRecorder($recorder);

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    foreach ($steps as $step) {
        if ($step === 'upload') {
            $file = fopen('php://temp', 'w+');
            fwrite($file, 'xyz');
            rewind($file);
            curl_setopt_array($ch, [CURLOPT_UPLOAD => true, CURLOPT_INFILE => $file, CURLOPT_INFILESIZE => 3]);

            continue;
        }

        curl_setopt($ch, $step[0], $step[1]);
    }

    $echo = json_decode((string) curl_exec($ch), true);
    $recorder->flush();

    expect($sink->all())->toHaveCount(1);
    $exchange = $sink->all()[0];

    return [$exchange, [
        'method' => (string) $exchange->responseHeaders->first('X-Method'),
        'body' => is_array($echo) ? (string) $echo['body'] : '',
        'content_type' => is_array($echo) ? $echo['content_type'] : null,
    ]];
}

/**
 * curl picks a random boundary; the record uses its own of the same length.
 */
function sameBoundary(string $text): string
{
    return (string) preg_replace('/-{24}[A-Za-z0-9]{22}/', '<boundary>', $text);
}

it('records the method, body and content type the server received', function (array $steps, bool $readable): void {
    [$exchange, $server] = sentAndRecorded($steps);

    expect($exchange->method)->toBe($server['method']);

    if ($server['body'] === '') {
        expect($exchange->requestBody->bytes)->toBeNull()
            ->and($exchange->requestBody->omittedReason)->toBeNull();

        return;
    }

    if (!$readable) {
        expect($exchange->requestBody->omittedReason)->toBe('not-readable');

        return;
    }

    expect(sameBoundary((string) $exchange->requestBody->bytes))->toBe(sameBoundary($server['body']))
        ->and($exchange->requestBody->size)->toBe(strlen($server['body']))
        ->and(sameBoundary((string) $exchange->requestBody->contentType))->toBe(sameBoundary((string) $server['content_type']));
})->with([
    'POSTFIELDS then POST=false' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_POST, false]], true],
    'POSTFIELDS, POST=false, POST=true' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_POST, false], [CURLOPT_POST, true]], true],
    'POSTFIELDS, HTTPGET, POST=true' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_HTTPGET, true], [CURLOPT_POST, true]], true],
    'POSTFIELDS, NOBODY 1, NOBODY 0' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_NOBODY, true], [CURLOPT_NOBODY, false]], true],
    'POSTFIELDS then NOBODY 0' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_NOBODY, false]], true],
    'NOBODY then POSTFIELDS' => [[[CURLOPT_NOBODY, true], [CURLOPT_POSTFIELDS, 'a=1']], true],
    'NOBODY, POSTFIELDS, POST=true' => [[[CURLOPT_NOBODY, true], [CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_POST, true]], true],
    'NOBODY then array POSTFIELDS' => [[[CURLOPT_NOBODY, true], [CURLOPT_POSTFIELDS, ['a' => '1']]], true],
    'UPLOAD' => [['upload'], false],
    'PUT' => [[[CURLOPT_PUT, true], [CURLOPT_INFILESIZE, 0]], false],
    'UPLOAD then UPLOAD=false' => [['upload', [CURLOPT_UPLOAD, false]], true],
    'UPLOAD then POST=true' => [['upload', [CURLOPT_POST, true]], false],
    'UPLOAD then POSTFIELDS' => [['upload', [CURLOPT_POSTFIELDS, 'a=1']], true],
    'POSTFIELDS then UPLOAD' => [[[CURLOPT_POSTFIELDS, 'a=1'], 'upload'], false],
    'UPLOAD then HTTPGET' => [['upload', [CURLOPT_HTTPGET, true]], true],
    'UPLOAD then NOBODY' => [['upload', [CURLOPT_NOBODY, true]], true],
    'NOBODY then UPLOAD' => [[[CURLOPT_NOBODY, true], 'upload'], false],
    'POST=true alone' => [[[CURLOPT_POST, true]], true],
    'POSTFIELDS null' => [[[CURLOPT_POSTFIELDS, null]], true],
    'empty array POSTFIELDS' => [[[CURLOPT_POSTFIELDS, []]], true],
    'array POSTFIELDS' => [[[CURLOPT_POSTFIELDS, ['a' => '1', 'b' => 'x y', 5 => 7, 'n' => null, 't' => true, 'f' => 1.5]]], true],
    'array POSTFIELDS, awkward names' => [[[CURLOPT_POSTFIELDS, ['we"ird' => "v\r\n1", "cr\rlf\n" => '%']]], true],
    'array POSTFIELDS then POST=true' => [[[CURLOPT_POSTFIELDS, ['a' => '1']], [CURLOPT_POST, true]], true],
    'POST=true then array POSTFIELDS' => [[[CURLOPT_POST, true], [CURLOPT_POSTFIELDS, ['a' => '1']]], true],
    'array then string POSTFIELDS' => [[[CURLOPT_POSTFIELDS, ['a' => '1']], [CURLOPT_POSTFIELDS, 's=2']], true],
    'string then array POSTFIELDS' => [[[CURLOPT_POSTFIELDS, 's=2'], [CURLOPT_POSTFIELDS, ['a' => '1']]], true],
    'array POSTFIELDS with an explicit multipart type' => [[[CURLOPT_POSTFIELDS, ['a' => '1']], [CURLOPT_HTTPHEADER, ['Content-Type: multipart/form-data']]], true],
    'array POSTFIELDS under another type' => [[[CURLOPT_POSTFIELDS, ['a' => '1']], [CURLOPT_HTTPHEADER, ['Content-Type: multipart/mixed']]], false],
    'nested array POSTFIELDS' => [[[CURLOPT_POSTFIELDS, ['a' => ['b' => '1']]]], false],
    'CUSTOMREQUEST DELETE' => [[[CURLOPT_CUSTOMREQUEST, 'DELETE']], true],
    'CUSTOMREQUEST DELETE with a body' => [[[CURLOPT_CUSTOMREQUEST, 'DELETE'], [CURLOPT_POSTFIELDS, 'a=1']], true],
    'POSTFIELDS, POST=false, CUSTOMREQUEST PATCH' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_POST, false], [CURLOPT_CUSTOMREQUEST, 'PATCH']], true],
    'CUSTOMREQUEST GET with a body' => [[[CURLOPT_CUSTOMREQUEST, 'GET'], [CURLOPT_POSTFIELDS, 'a=1']], true],
    'CUSTOMREQUEST PATCH, POSTFIELDS, NOBODY' => [[[CURLOPT_CUSTOMREQUEST, 'PATCH'], [CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_NOBODY, true]], true],
    'CUSTOMREQUEST PATCH with UPLOAD' => [[[CURLOPT_CUSTOMREQUEST, 'PATCH'], 'upload'], false],
    'CUSTOMREQUEST then null' => [[[CURLOPT_CUSTOMREQUEST, 'DELETE'], [CURLOPT_CUSTOMREQUEST, null]], true],
    'HTTPGET=false changes nothing' => [[[CURLOPT_POSTFIELDS, 'a=1'], [CURLOPT_HTTPGET, false]], true],
]);

it('says the multipart body is rebuilt, not the bytes on the wire', function (): void {
    [$exchange] = sentAndRecorded([[CURLOPT_POSTFIELDS, ['a' => '1']]]);

    expect($exchange->context['request_body'] ?? null)->toBe('reconstructed');

    [$exchange] = sentAndRecorded([[CURLOPT_POSTFIELDS, 'a=1']]);

    expect($exchange->context)->not->toHaveKey('request_body');
});

it('never stores a multipart field value the redactor could not inspect', function (): void {
    // Multipart is not a capturable type by default, so the fields are not
    // stored at all; with a body path configured, nothing the path named can
    // survive either way.
    [$exchange] = sentAndRecorded([[CURLOPT_POSTFIELDS, ['password' => 'ordinary-secret', 'card' => '4111 1111 1111 1111']]], redact: true, bodyPaths: ['password']);

    expect((string) $exchange->requestBody->bytes)->not->toContain('ordinary-secret')
        ->not->toContain('4111');

    [$exchange] = sentAndRecorded([[CURLOPT_POSTFIELDS, ['card' => '4111 1111 1111 1111']]], redact: true);

    expect((string) $exchange->requestBody->bytes)->not->toContain('4111');

    // An operator who makes multipart capturable gets the detectors on the
    // raw field values, and a named body path, which cannot be applied to
    // multipart, drops the body rather than keep what it named.
    $multipart = [...RedactionConfig::DEFAULT_CAPTURABLE_TYPES, 'multipart/form-data'];

    [$exchange] = sentAndRecorded([[CURLOPT_POSTFIELDS, ['card' => '4111 1111 1111 1111', 'note' => 'hello']]], redact: true, capturable: $multipart);

    expect((string) $exchange->requestBody->bytes)->toContain('hello')
        ->not->toContain('4111');

    [$exchange] = sentAndRecorded([[CURLOPT_POSTFIELDS, ['password' => 'ordinary-secret']]], redact: true, bodyPaths: ['password'], capturable: $multipart);

    expect((string) $exchange->requestBody->bytes)->not->toContain('ordinary-secret');
});
