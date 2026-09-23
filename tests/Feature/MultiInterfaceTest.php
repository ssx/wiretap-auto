<?php

declare(strict_types=1);

/**
 * Real transfers against a real socket, through the real ext-opentelemetry
 * hooks. The claim being tested — that async traffic is captured — cannot be
 * made honestly against mocks, because what was broken was which ext-curl
 * functions the hooks were attached to.
 */

/**
 * Start a one-response-per-connection server on a port the OS picks, and
 * return its base URL. Fixed ports collide on shared CI runners.
 */
function multiTestServer(): string
{
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);

    if ($server === false) {
        throw new RuntimeException("cannot listen: {$error}");
    }

    $name = (string) stream_socket_get_name($server, false);
    $port = (int) substr($name, (int) strrpos($name, ':') + 1);

    if (pcntl_fork() !== 0) {
        fclose($server);

        // Give the child a moment to reach accept().
        usleep(250_000);

        return "http://127.0.0.1:{$port}";
    }

    while (true) {
        $connection = @stream_socket_accept($server, 5);

        if ($connection === false) {
            break;
        }

        $request = (string) fread($connection, 4096);

        // Answers the status line and the start of the body, then stalls:
        // a transfer that is still running when the test gives up on it.
        if (str_starts_with($request, 'GET /slow')) {
            fwrite($connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"partial\":");
            usleep(1_500_000);
            @fclose($connection);

            continue;
        }

        $body = '{"ok":1}';
        fwrite(
            $connection,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            . strlen($body) . "\r\n\r\n" . $body,
        );
        fclose($connection);
    }

    exit(0);
}

/**
 * @return list<array<string, mixed>>
 */
function recordedIn(string $dir): array
{
    Ssx\Wiretap\Wiretap::recorder()->flush();

    $file = glob($dir . '/*.ndjson')[0] ?? null;

    if ($file === null) {
        return [];
    }

    $records = [];

    foreach (array_filter(explode("\n", (string) file_get_contents($file))) as $line) {
        $decoded = json_decode($line, true);

        if (is_array($decoded)) {
            $records[] = $decoded;
        }
    }

    return $records;
}

/**
 * @param  list<array<string, mixed>> $records
 * @return list<string>
 */
function recordedPaths(array $records): array
{
    $paths = array_map(
        static fn (array $r): string => (string) parse_url((string) ($r['uri'] ?? ''), PHP_URL_PATH),
        $records,
    );

    sort($paths);

    return $paths;
}

/**
 * Run the multi loop until nothing is running or the time is up, without
 * ever asking curl_multi_info_read how anything ended.
 */
function runMultiFor(\CurlMultiHandle $multi, float $seconds): void
{
    $until = microtime(true) + $seconds;

    do {
        curl_multi_exec($multi, $running);

        if ($running) {
            curl_multi_select($multi, 0.05);
        }
    } while ($running && microtime(true) < $until);
}

function drainMulti(\CurlMultiHandle $multi): void
{
    do {
        $status = curl_multi_exec($multi, $running);

        if ($running) {
            curl_multi_select($multi);
        }
    } while ($running && $status === CURLM_OK);
}

beforeEach(function (): void {
    if (!extension_loaded('opentelemetry') || !function_exists('pcntl_fork')) {
        $this->markTestSkipped('needs ext-opentelemetry and ext-pcntl');
    }

    $this->dir = sys_get_temp_dir() . '/wiretap-multi-' . bin2hex(random_bytes(6));
    putenv('WIRETAP_ENABLED=1');
    putenv('WIRETAP_PATH=' . $this->dir);

    // No driver is constructed here on purpose. The package registers its
    // hooks from _register.php at autoload, and registering a second driver
    // attaches a second set of hooks to the same functions — which records
    // every transfer twice and looks exactly like a duplication bug in the
    // package.
    Ssx\Wiretap\Wiretap::reset();
});

afterEach(function (): void {
    putenv('WIRETAP_ENABLED');
    putenv('WIRETAP_PATH');
    Ssx\Wiretap\Wiretap::reset();

    if (!is_dir($this->dir)) {
        return;
    }

    array_map('unlink', glob($this->dir . '/*') ?: []);
    rmdir($this->dir);
});

it('captures a raw curl_multi loop, body included', function (): void {
    $base = multiTestServer();

    $multi = curl_multi_init();
    $handle = curl_init("{$base}/raw-multi");
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    curl_multi_add_handle($multi, $handle);
    drainMulti($multi);

    // curl_multi_info_read is how curl says a transfer finished and how.
    while (curl_multi_info_read($multi)) {
    }

    curl_multi_remove_handle($multi, $handle);
    curl_multi_close($multi);

    $records = recordedIn($this->dir);

    expect($records)->toHaveCount(1)
        ->and($records[0]['status'])->toBe(200)
        // RETURNTRANSFER, so there is a returned string to record.
        ->and($records[0]['response']['body']['bytes'])->toBe('{"ok":1}');
});

it('records a transfer once even when both completion paths are used', function (): void {
    // Guzzle's handler calls curl_multi_info_read; other code only ever calls
    // curl_multi_remove_handle. Both are hooked, so a loop that does both must
    // still produce exactly one record.
    $base = multiTestServer();

    $multi = curl_multi_init();
    $handle = curl_init("{$base}/once");
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    curl_multi_add_handle($multi, $handle);
    drainMulti($multi);

    while (curl_multi_info_read($multi)) {
        // Drain, exactly as a real event loop does.
    }

    curl_multi_remove_handle($multi, $handle);
    curl_multi_close($multi);

    expect(recordedIn($this->dir))->toHaveCount(1);
});

it('captures Guzzle async requests and pools', function (): void {
    $base = multiTestServer();
    $client = new GuzzleHttp\Client();

    $client->get("{$base}/sync");
    $client->getAsync("{$base}/async")->wait();

    $requests = (function () use ($base) {
        yield new GuzzleHttp\Psr7\Request('GET', "{$base}/pool-1");
        yield new GuzzleHttp\Psr7\Request('GET', "{$base}/pool-2");
    })();

    (new GuzzleHttp\Pool($client, $requests, ['concurrency' => 2]))->promise()->wait();

    expect(recordedPaths(recordedIn($this->dir)))
        ->toBe(['/async', '/pool-1', '/pool-2', '/sync']);
});

it('captures Symfony CurlHttpClient, which never calls curl_exec', function (): void {
    $base = multiTestServer();

    $client = new Symfony\Component\HttpClient\CurlHttpClient();
    $client->request('GET', "{$base}/symfony")->getContent();

    $records = recordedIn($this->dir);

    expect($records)->toHaveCount(1)
        ->and($records[0]['status'])->toBe(200);
});

/**
 * curl_multi_remove_handle() is also how a transfer is cancelled: Guzzle's
 * cancel(), a Symfony response destroyed early, an event loop giving up. Only
 * curl_multi_info_read says a transfer finished and how, so a transfer
 * removed without it has no known outcome and must not read as a success.
 */
describe('a transfer removed before curl reported it complete', function (): void {
    it('is not recorded as a success when cancelled mid-transfer', function (): void {
        $base = multiTestServer();

        $multi = curl_multi_init();
        $handle = curl_init("{$base}/slow");
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_multi_add_handle($multi, $handle);
        runMultiFor($multi, 0.4);
        curl_multi_remove_handle($multi, $handle);

        $records = recordedIn($this->dir);

        expect($records)->toHaveCount(1)
            ->and($records[0]['error']['message'] ?? null)->toContain('removed before curl reported it complete')
            // A partial body is not the response; it must not pass for one.
            ->and($records[0]['response']['body']['bytes'] ?? null)->toBeNull()
            ->and($records[0]['response']['body']['omitted_reason'] ?? null)->toBe('not-readable');
    });

    it('is not recorded as a success when it timed out and nobody read the result', function (): void {
        $base = multiTestServer();

        $multi = curl_multi_init();
        $handle = curl_init("{$base}/slow");
        curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 300]);
        curl_multi_add_handle($multi, $handle);
        runMultiFor($multi, 3.0);

        // curl gave up on it, but only curl_multi_info_read would have said
        // so: curl_errno() on the handle is still 0 here.
        expect(curl_errno($handle))->toBe(0);

        curl_multi_remove_handle($multi, $handle);

        $records = recordedIn($this->dir);

        expect($records)->toHaveCount(1)
            ->and($records[0]['error'] ?? null)->not->toBeNull();
    });

    it('is not recorded as a success when it never started', function (): void {
        $base = multiTestServer();

        $multi = curl_multi_init();
        $handle = curl_init("{$base}/never");
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_multi_add_handle($multi, $handle);
        curl_multi_remove_handle($multi, $handle);

        $records = recordedIn($this->dir);

        expect($records)->toHaveCount(1)
            ->and($records[0]['error']['message'] ?? null)->toContain('removed before curl reported it complete')
            ->and($records[0]['status'] ?? null)->toBeNull();
    });

    it('keeps the outcome curl reported when it timed out and the loop read it', function (): void {
        $base = multiTestServer();

        $multi = curl_multi_init();
        $handle = curl_init("{$base}/slow");
        curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 300]);
        curl_multi_add_handle($multi, $handle);
        drainMulti($multi);

        while (curl_multi_info_read($multi)) {
        }

        curl_multi_remove_handle($multi, $handle);

        $records = recordedIn($this->dir);

        expect($records)->toHaveCount(1)
            ->and($records[0]['error']['errno'] ?? null)->toBe(CURLE_OPERATION_TIMEDOUT);
    });
});

/**
 * An async transfer belongs to the unit of work that started it. A worker
 * that adds a transfer during one job and drains it during the next must not
 * file it under the next job.
 */
it('files a multi transfer under the correlation it started in', function (): void {
    $base = multiTestServer();

    Ssx\Wiretap\Correlation::start('job-a');

    $multi = curl_multi_init();
    $handle = curl_init("{$base}/async-job");
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    curl_multi_add_handle($multi, $handle);

    Ssx\Wiretap\Correlation::start('job-b');
    // job-b's own first call, so job-b's sequence has moved on as well.
    Ssx\Wiretap\Correlation::nextSequence();

    drainMulti($multi);

    while (curl_multi_info_read($multi)) {
    }

    curl_multi_remove_handle($multi, $handle);

    $records = recordedIn($this->dir);

    Ssx\Wiretap\Correlation::reset();

    expect($records)->toHaveCount(1)
        ->and($records[0]['correlation_id'])->toBe('job-a')
        ->and($records[0]['sequence'])->toBe(0);
});
