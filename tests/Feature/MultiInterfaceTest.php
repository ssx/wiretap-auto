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

        fread($connection, 4096);
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
