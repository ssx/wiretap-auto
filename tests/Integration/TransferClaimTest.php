<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Pool;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;
use Ssx\Wiretap\Auto\Wiretap;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\TransferClaim;
use Symfony\Component\HttpClient\CurlHttpClient;
use Symfony\Component\HttpClient\RetryableHttpClient;

/**
 * A bridge claims a transfer by setting TransferClaim::KEY in its request
 * options. The hooks must then record nothing for it on any hop, because the
 * bridge's record of the same call is the one with bodies, and must never
 * change what the client does or what it reports.
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
    $this->recorder = new Recorder(sink: $this->sink, blocklist: new Blocklist());
    Wiretap::setRecorder($this->recorder);
    $this->base = 'http://127.0.0.1:' . TEST_SERVER_PORT;

    // Every deprecation or warning raised anywhere in a claimed call, whatever
    // error_reporting says: Guzzle raises its deprecations under @.
    $this->raised = [];
    set_error_handler(function (int $level, string $message): bool {
        $this->raised[] = $message;

        return true;
    });
});

afterEach(function (): void {
    restore_error_handler();
});

function uris(InMemorySink $sink): array
{
    return array_map(static fn ($e): string => $e->uri, $sink->all());
}

it('honours the claim once its hooks are in', function (): void {
    expect(TransferClaim::isHonoured())->toBeTrue()
        ->and(Wiretap::diagnostics()['transfer_claim'])->toBe('honoured');
});

it('records nothing for claimed Guzzle calls: sync, async, pool, redirect and retry', function (): void {
    $flaky = $this->base . '/flaky/' . bin2hex(random_bytes(4));
    $stack = HandlerStack::create();
    $stack->push(Middleware::retry(
        static fn (int $retries, RequestInterface $request, $response = null): bool => $retries < 2 && $response?->getStatusCode() === 503,
    ));
    $client = new Client(['handler' => $stack, 'http_errors' => false]);
    $claimed = [TransferClaim::KEY => true];

    $statuses = [
        $client->get($this->base . '/echo?sync', $claimed)->getStatusCode(),
        $client->getAsync($this->base . '/echo?async', $claimed)->wait()->getStatusCode(),
        $client->get($this->base . '/redirect', $claimed)->getStatusCode(),
        $client->get($flaky, $claimed)->getStatusCode(),
    ];

    $pooled = [];
    (new Pool($client, [new Request('GET', $this->base . '/echo?pool=1'), new Request('GET', $this->base . '/echo?pool=2')], [
        'options' => $claimed,
        'fulfilled' => static function (Response $response) use (&$pooled): void {
            $pooled[] = $response->getStatusCode();
        },
    ]))->promise()->wait();

    $this->recorder->flush();

    // The client behaved exactly as without the claim: redirect followed,
    // 503 retried to a 200.
    expect($statuses)->toBe([200, 200, 200, 200])
        ->and($pooled)->toBe([200, 200])
        ->and($this->sink->all())->toBeEmpty()
        ->and($this->raised)->toBe([]);
});

it('still records unclaimed Guzzle calls', function (): void {
    $client = new Client(['http_errors' => false]);

    $client->get($this->base . '/echo?sync');
    $client->getAsync($this->base . '/echo?async')->wait();
    $client->get($this->base . '/echo?other', [TransferClaim::KEY => false]);
    $this->recorder->flush();

    expect(uris($this->sink))->toBe([
        $this->base . '/echo?sync',
        $this->base . '/echo?async',
        $this->base . '/echo?other',
    ]);
});

it('claims each Guzzle handle afresh when the factory reuses it', function (): void {
    // CurlFactory pools handles and curl_reset()s them on release. The claim
    // goes with the reset, so the next, unclaimed request on the same handle
    // is recorded.
    $client = new Client(['http_errors' => false]);

    $client->get($this->base . '/echo?claimed', [TransferClaim::KEY => true]);
    $client->get($this->base . '/echo?after');
    $this->recorder->flush();

    expect(uris($this->sink))->toBe([$this->base . '/echo?after']);
});

it('records nothing for claimed Symfony calls: plain, redirect and retry', function (): void {
    $flaky = $this->base . '/flaky/' . bin2hex(random_bytes(4));
    $client = new CurlHttpClient();
    $claimed = ['extra' => [TransferClaim::KEY => true]];

    $plain = $client->request('GET', $this->base . '/echo?plain', $claimed);
    $redirect = $client->request('GET', $this->base . '/redirect', $claimed);
    $retried = (new RetryableHttpClient($client, null, 2))->request('GET', $flaky, $claimed);

    $statuses = [$plain->getStatusCode(), $redirect->getStatusCode(), $retried->getStatusCode()];
    $redirectedTo = $redirect->getInfo('url');
    $plain->getContent();
    $redirect->getContent();
    $retried->getContent();
    $this->recorder->flush();

    expect($statuses)->toBe([200, 200, 200])
        ->and($redirectedTo)->toBe($this->base . '/echo?from=redirect')
        ->and($this->sink->all())->toBeEmpty()
        ->and($this->raised)->toBe([]);
});

it('still records unclaimed Symfony calls', function (): void {
    $client = new CurlHttpClient();

    $client->request('GET', $this->base . '/echo?unclaimed')->getContent();
    $this->recorder->flush();

    expect(uris($this->sink))->toBe([$this->base . '/echo?unclaimed']);
});

it('records a claimed request whose handle it cannot see being built, and changes nothing', function (): void {
    // Stands in for a custom CurlFactoryInterface, or for Guzzle moving its
    // internals: the claim is in the options, but no hook sees the handle
    // being made. The fallback is today's behaviour, a second record.
    $handler = static function (RequestInterface $request, array $options) {
        $ch = curl_init((string) $request->getUri());
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true]);
        $body = curl_exec($ch);

        return Create::promiseFor(new Response(200, [], (string) $body));
    };

    $response = (new Client(['handler' => HandlerStack::create($handler)]))
        ->get($this->base . '/echo?custom', [TransferClaim::KEY => true]);
    $this->recorder->flush();

    expect($response->getStatusCode())->toBe(200)
        ->and(json_decode((string) $response->getBody(), true)['path'] ?? null)->toBe('/echo?custom')
        ->and(uris($this->sink))->toBe([$this->base . '/echo?custom'])
        ->and($this->raised)->toBe([]);
});

it('honours the claim in a process that autoloads the package', function (): void {
    expect(honouredInFreshProcess(['WIRETAP_DISABLE_AUTO' => 'false']))->toBe('yes');
});
