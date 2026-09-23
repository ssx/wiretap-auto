<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\OtelHookDriver;
use Ssx\Wiretap\Auto\Wiretap;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Wiretap as Core;

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
        // The headers the application configured, marked as such: libcurl's
        // own additions are only knowable through CURLINFO_HEADER_OUT.
        ->and($exchange->requestHeaders->first('Content-Type'))->toBe('application/json')
        ->and($exchange->context['request_headers'] ?? null)->toBe('configured')
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

it('writes to a recorder set on the core holder, not a second one of its own', function (): void {
    // Two global holders would mean a framework can wire up a properly
    // configured recorder, set it on one, and have the live hooks go on
    // writing to the other. There must be exactly one.
    $sink = new InMemorySink();
    Core::setRecorder(new Recorder(sink: $sink, blocklist: new Blocklist()));

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);

    Core::recorder()->flush();

    expect($sink->all())->toHaveCount(1)
        ->and(Wiretap::recorder())->toBe(Core::recorder());
});

it('exposes the same recorder through either facade', function (): void {
    $recorder = new Recorder(sink: new InMemorySink());

    Wiretap::setRecorder($recorder);

    expect(Core::recorder())->toBe($recorder)
        ->and(Wiretap::recorder())->toBe($recorder);
});

it('lets a handle whose callbacks refer back to its owner be freed', function (): void {
    // The common SDK shape: an object owns a handle, and the handle's
    // callbacks are closures or methods bound to that object. On PHP 8.2 a
    // WeakMap does not collect a cycle that runs from a value back to its own
    // key, so a shadow state holding those callbacks kept the handle, the
    // owner and everything it referenced alive for the life of the process —
    // and once the registry filled, capture stopped everywhere.
    $recorder = useRecorder($this->sink);
    $freed = new ArrayObject();
    $url = 'http://127.0.0.1:' . TEST_SERVER_PORT . '/owned';

    for ($i = 0; $i < 20; ++$i) {
        $owner = new class ($url, $freed) {
            public \CurlHandle $handle;

            public function __construct(string $url, private ArrayObject $freed)
            {
                $this->handle = curl_init($url);
                curl_setopt($this->handle, CURLOPT_HEADERFUNCTION, fn ($ch, string $line): int => strlen($line));
                curl_setopt($this->handle, CURLOPT_WRITEFUNCTION, [$this, 'onBody']);
            }

            public function onBody(\CurlHandle $ch, string $data): int
            {
                return strlen($data);
            }

            public function __destruct()
            {
                $this->freed->append(true);
            }
        };

        curl_exec($owner->handle);
        unset($owner);
    }

    gc_collect_cycles();
    $recorder->flush();

    expect(count($freed))->toBe(20)
        ->and($this->sink->all())->toHaveCount(20);
});

it('does not put request headers where the application can read them', function (): void {
    // CURLINFO_HEADER_OUT makes the sent headers, Authorization included,
    // part of curl_getinfo(). Guzzle copies that into handler stats and into
    // exception context, which is how it reaches logs and error trackers.
    $recorder = useRecorder($this->sink);

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer app-secret', 'X-Tenant: alpha'],
    ]);
    curl_exec($ch);
    $recorder->flush();

    $exchange = $this->sink->all()[0];

    expect(curl_getinfo($ch))->not->toHaveKey('request_header')
        ->and(curl_getinfo($ch, CURLINFO_HEADER_OUT))->toBeFalse()
        // The record falls back to the headers the application configured,
        // and says that is what they are.
        ->and($exchange->requestHeaders->first('X-Tenant'))->toBe('alpha')
        ->and($exchange->context['request_headers'] ?? null)->toBe('configured');
});

it('keeps Guzzle handler stats free of request headers', function (): void {
    useRecorder($this->sink);
    $stats = null;

    (new GuzzleHttp\Client())->get('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo', [
        'headers' => ['Authorization' => 'Bearer app-secret'],
        'on_stats' => static function (GuzzleHttp\TransferStats $s) use (&$stats): void {
            $stats = $s->getHandlerStats();
        },
    ]);

    expect($stats)->toBeArray()
        ->and($stats)->not->toHaveKey('request_header');
});

it('uses the sent headers when the application asked curl for them itself', function (): void {
    $recorder = useRecorder($this->sink);

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLINFO_HEADER_OUT => true]);
    curl_exec($ch);
    $recorder->flush();

    $exchange = $this->sink->all()[0];

    expect($exchange->requestHeaders->has('Host'))->toBeTrue()
        ->and($exchange->context)->not->toHaveKey('request_headers');
});

it('leaves verbose output working when the application turns it on after a capture', function (): void {
    useRecorder($this->sink);

    $ch = curl_init('http://127.0.0.1:' . TEST_SERVER_PORT . '/echo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);

    $stderr = fopen('php://temp', 'w+');
    curl_setopt($ch, CURLOPT_STDERR, $stderr);
    curl_setopt($ch, CURLOPT_VERBOSE, true);
    curl_exec($ch);
    rewind($stderr);

    expect((string) stream_get_contents($stderr))->not->toBe('');
});

it('still calls a private header callback, and declines capture rather than drop it', function (): void {
    // curl checks callability from the application's scope, so a private
    // method is a valid callback there. From ours it is not callable at all,
    // and the wrapper used to replace it with nothing to chain onto.
    $recorder = useRecorder($this->sink);

    $sdk = new class ('http://127.0.0.1:' . TEST_SERVER_PORT . '/private') {
        public int $headers = 0;

        public function __construct(private string $url)
        {
        }

        public function run(): mixed
        {
            $ch = curl_init($this->url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, [$this, 'onHeader']);

            return curl_exec($ch);
        }

        private function onHeader(\CurlHandle $ch, string $line): int
        {
            ++$this->headers;

            return strlen($line);
        }
    };

    $result = $sdk->run();
    $recorder->flush();

    expect($result)->toBeString()
        ->and($sdk->headers)->toBeGreaterThan(0)
        // Without a header capture we cannot trust, there is no true record
        // to write, so there is none.
        ->and($this->sink->all())->toBeEmpty();
});
