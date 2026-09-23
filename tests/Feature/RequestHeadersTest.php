<?php

declare(strict_types=1);

use Ssx\Wiretap\Auto\Internal\HandleState;
use Ssx\Wiretap\Auto\Internal\RequestHeaders;

/**
 * The rebuilt request headers, checked against what libcurl itself reports
 * sending through CURLINFO_HEADER_OUT for the same options, on a real
 * transfer. No extension needed: this is curl and the rebuilder alone.
 */

/**
 * @param array<int, mixed> $options
 *
 * @return array{sent: list<string>, rebuilt: list<string>}
 */
function sentAndRebuilt(string $path, array $options): array
{
    $url = str_starts_with($path, 'http') ? $path : 'http://127.0.0.1:' . TEST_SERVER_PORT . $path;

    $ch = curl_init($url);
    curl_setopt_array($ch, $options + [CURLOPT_RETURNTRANSFER => true, CURLINFO_HEADER_OUT => true]);
    curl_exec($ch);

    $sent = preg_split('/\r\n/', trim((string) curl_getinfo($ch, CURLINFO_HEADER_OUT))) ?: [];
    array_shift($sent);

    $state = new HandleState();
    $state->set(CURLOPT_URL, $url);
    $state->setMany($options);

    return [
        'sent' => array_values($sent),
        'rebuilt' => RequestHeaders::reconstruct(
            $state,
            (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL),
            (int) curl_getinfo($ch, CURLINFO_REDIRECT_COUNT),
        ),
    ];
}

it('rebuilds exactly what curl sent, in the order it sent it', function (string $path, array $options): void {
    ['sent' => $sent, 'rebuilt' => $rebuilt] = sentAndRebuilt($path, $options);

    expect($rebuilt)->toBe($sent);
})->with([
    'plain GET' => ['/echo', []],
    'form POST' => ['/echo', [CURLOPT_POSTFIELDS => 'a=1&b=2']],
    'empty POST body' => ['/echo', [CURLOPT_POSTFIELDS => '']],
    'custom method with a body' => ['/echo', [CURLOPT_CUSTOMREQUEST => 'PATCH', CURLOPT_POSTFIELDS => 'abc']],
    'HEAD' => ['/echo', [CURLOPT_NOBODY => true]],
    'PUT with a known size' => ['/echo', [CURLOPT_PUT => true, CURLOPT_INFILESIZE => 0, CURLOPT_READFUNCTION => static fn (): string => '']],
    'user agent, referer, cookie, every encoding' => ['/echo', [CURLOPT_USERAGENT => 'UA/1', CURLOPT_REFERER => 'http://ref.test/', CURLOPT_COOKIE => 'a=1; b=2', CURLOPT_ENCODING => '']],
    'one encoding' => ['/echo', [CURLOPT_ENCODING => 'gzip']],
    'USERPWD' => ['/echo', [CURLOPT_USERPWD => 'user:pass']],
    'USERNAME and PASSWORD' => ['/echo', [CURLOPT_USERNAME => 'user', CURLOPT_PASSWORD => 'pass']],
    'USERNAME alone' => ['/echo', [CURLOPT_USERNAME => 'user']],
    'USERNAME after USERPWD' => ['/echo', [CURLOPT_USERPWD => 'first:pass', CURLOPT_USERNAME => 'second']],
    'credentials in the URL' => ['http://us%40r:p%3Ass@127.0.0.1:' . TEST_SERVER_PORT . '/echo', []],
    'USERPWD over URL credentials' => ['http://url:pw@127.0.0.1:' . TEST_SERVER_PORT . '/echo', [CURLOPT_USERPWD => 'opt:pw']],
    'bearer' => ['/echo', [CURLOPT_XOAUTH2_BEARER => 'tok', CURLOPT_HTTPAUTH => CURLAUTH_BEARER]],
    'bearer without HTTPAUTH sends nothing' => ['/echo', [CURLOPT_XOAUTH2_BEARER => 'tok']],
    'CURLAUTH_ANY sends nothing up front' => ['/echo', [CURLOPT_USERPWD => 'u:p', CURLOPT_HTTPAUTH => CURLAUTH_ANY]],
    'application headers replace, remove and add' => ['/echo', [
        CURLOPT_USERAGENT => 'UA/1',
        CURLOPT_POSTFIELDS => 'x',
        CURLOPT_HTTPHEADER => ['User-Agent: Mine', 'Accept:', 'X-A: 1', 'X-Empty;', 'Host: other.test', 'X-Bad', ': nameless'],
    ]],
    'application Authorization wins over USERPWD' => ['/echo', [CURLOPT_USERPWD => 'u:p', CURLOPT_HTTPHEADER => ['Authorization: Custom z']]],
    'application Content-Type' => ['/echo', [CURLOPT_POSTFIELDS => '{}', CURLOPT_HTTPHEADER => ['Content-Type: application/json']]],
    'Host removed' => ['/echo', [CURLOPT_HTTPHEADER => ['Host:']]],
    'CURLOPT_PORT' => ['http://127.0.0.1/echo', [CURLOPT_PORT => TEST_SERVER_PORT]],
    'HTTP/1.0' => ['/echo', [CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_0]],
    // libcurl's method state, which decides whether the body headers go out.
    'POSTFIELDS then POST=false sends a GET' => ['/echo', [CURLOPT_POSTFIELDS => 'a=1', CURLOPT_POST => false]],
    'POSTFIELDS kept through HTTPGET' => ['/echo', [CURLOPT_POSTFIELDS => 'a=1', CURLOPT_HTTPGET => true, CURLOPT_POST => true]],
    'NOBODY then POSTFIELDS is still HEAD' => ['/echo', [CURLOPT_NOBODY => true, CURLOPT_POSTFIELDS => 'a=1']],
    'UPLOAD then POSTFIELDS is a POST' => ['/echo', [CURLOPT_UPLOAD => true, CURLOPT_INFILESIZE => 0, CURLOPT_READFUNCTION => static fn (): string => '', CURLOPT_POSTFIELDS => 'a=1']],
    'POSTFIELDS then UPLOAD is a PUT' => ['/echo', [CURLOPT_POSTFIELDS => 'a=1', CURLOPT_UPLOAD => true, CURLOPT_INFILESIZE => 0, CURLOPT_READFUNCTION => static fn (): string => '']],
    'custom method after POST=false sends no body' => ['/echo', [CURLOPT_POSTFIELDS => 'a=1', CURLOPT_POST => false, CURLOPT_CUSTOMREQUEST => 'PATCH']],
    'custom GET with a body' => ['/echo', [CURLOPT_CUSTOMREQUEST => 'GET', CURLOPT_POSTFIELDS => 'a=1']],
    'POSTFIELDS null is an empty body' => ['/echo', [CURLOPT_POSTFIELDS => null]],
    'redirect on the same host keeps auth, cookie and the auto referer, drops the body' => ['/redirect', [
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_USERPWD => 'u:p',
        CURLOPT_POSTFIELDS => 'x=1',
        CURLOPT_COOKIE => 'c=1',
        CURLOPT_AUTOREFERER => true,
    ]],
    'redirect to another host drops auth' => ['/xredirect', [CURLOPT_FOLLOWLOCATION => true, CURLOPT_USERPWD => 'u:p']],
    'redirect to another host with UNRESTRICTED_AUTH keeps it' => ['/xredirect', [CURLOPT_FOLLOWLOCATION => true, CURLOPT_USERPWD => 'u:p', CURLOPT_UNRESTRICTED_AUTH => true]],
]);

it('leaves out what the options do not determine, and invents nothing', function (string $path, array $options, array $unknown): void {
    ['sent' => $sent, 'rebuilt' => $rebuilt] = sentAndRebuilt($path, $options);

    $name = static fn (string $line): string => strtolower(strstr($line, ':', true) ?: $line);

    // Everything rebuilt was sent, byte for byte...
    expect(array_values(array_diff($rebuilt, $sent)))->toBe([])
        // ...and what is missing is exactly what cannot be known.
        ->and(array_values(array_unique(array_map($name, array_diff($sent, $rebuilt)))))->toBe($unknown);
})->with([
    'multipart boundary' => ['/echo', [CURLOPT_POSTFIELDS => ['a' => '1']], ['content-length', 'content-type']],
    'multipart boundary appended to the application\'s type' => ['/echo', [CURLOPT_POSTFIELDS => ['a' => '1'], CURLOPT_HTTPHEADER => ['Content-Type: multipart/form-data', 'X-A: 1']], ['content-length', 'content-type']],
    'Expect on a large body' => ['/echo', [CURLOPT_POSTFIELDS => str_repeat('a', 2 * 1024 * 1024)], ['expect']],
    'chunked upload' => ['/echo', [CURLOPT_PUT => true, CURLOPT_READFUNCTION => static fn (): string => ''], ['transfer-encoding', 'expect']],
    'cookies from curl\'s own jar' => ['/setcookie', [CURLOPT_FOLLOWLOCATION => true, CURLOPT_COOKIEFILE => '', CURLOPT_COOKIE => 'a=1'], ['cookie']],
]);

it('leaves out a password set without a user name, which libcurl versions disagree on', function (): void {
    ['sent' => $sent, 'rebuilt' => $rebuilt] = sentAndRebuilt('/echo', [CURLOPT_PASSWORD => 'pass']);

    // 8.22 sends `Authorization: Basic OnBhc3M=`; older builds send nothing.
    expect(array_values(array_diff($rebuilt, $sent)))->toBe([])
        ->and(preg_grep('/^Authorization:/i', $rebuilt))->toBe([]);
});
