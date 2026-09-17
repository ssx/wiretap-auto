<?php

declare(strict_types=1);

/**
 * A local HTTP server for the integration tests.
 *
 * Real hooks need real transfers. Pointing the tests at a public endpoint
 * would make them slow, flaky and dependent on someone else's uptime, so the
 * suite starts PHP's built-in server instead.
 */
const TEST_SERVER_PORT = 8799;

$docroot = sys_get_temp_dir() . '/wiretap-auto-test-server';

if (!is_dir($docroot)) {
    mkdir($docroot, 0o755, true);
}

file_put_contents($docroot . '/index.php', <<<'ROUTER'
<?php
header('Content-Type: application/json');
header('X-Test-Server: wiretap');
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'path' => $_SERVER['REQUEST_URI'],
    'body' => file_get_contents('php://input'),
]);
ROUTER);

$server = proc_open(
    sprintf('exec %s -S 127.0.0.1:%d -t %s', PHP_BINARY, TEST_SERVER_PORT, escapeshellarg($docroot)),
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes,
);

// Wait for it to accept connections rather than guessing at a sleep.
for ($i = 0; $i < 50; ++$i) {
    $socket = @fsockopen('127.0.0.1', TEST_SERVER_PORT, $errno, $errstr, 0.1);

    if ($socket !== false) {
        fclose($socket);

        break;
    }

    usleep(100_000);
}

register_shutdown_function(static function () use ($server): void {
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
});
