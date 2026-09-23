<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

/**
 * The request headers libcurl sends, rebuilt from the options it was given.
 *
 * Without CURLINFO_HEADER_OUT (which this package must not turn on, see
 * OtelHookDriver::installCaptureOptions) the only request headers on record
 * were the ones the application listed in CURLOPT_HTTPHEADER. libcurl adds
 * its own on top — Host, Accept, Authorization from CURLOPT_USERPWD, the
 * body's length and type — so a record could not be replayed: the server
 * would see a different request.
 *
 * Every rule here was measured against what libcurl 8 reports through
 * CURLINFO_HEADER_OUT, including the order it writes them in. Where the
 * options do not determine a header — Digest, NTLM or Negotiate, a
 * multipart boundary, cookies from curl's own jar, Expect, anything that
 * depends on what a redirect answered — it is left out rather than guessed.
 */
final class RequestHeaders
{
    /**
     * @param string $effectiveUrl the URL of the request these headers went with
     * @param int    $redirects    how many redirects curl followed to reach it
     *
     * @return list<string>
     */
    public static function reconstruct(HandleState $state, string $effectiveUrl, int $redirects): array
    {
        [$custom, $named] = self::custom($state->get(CURLOPT_HTTPHEADER));

        // An application header of the same name replaces curl's own, and
        // `Name:` removes it. Measured: curl writes a replacement Host where
        // its own would have gone, and every other application header after
        // its own leading block, in the order given.
        $mine = static fn (string $name): bool => !isset($named[strtolower($name)]);

        $lines = [];

        $host = self::customHost($custom);

        if ($host !== null) {
            $lines[] = $host;
        } elseif ($mine('Host') && ($own = self::host($state, $effectiveUrl)) !== null) {
            $lines[] = 'Host: ' . $own;
        }

        if ($mine('Authorization') && ($auth = self::authorization($state, $effectiveUrl, $redirects)) !== null) {
            $lines[] = 'Authorization: ' . $auth;
        }

        $userAgent = $state->get(CURLOPT_USERAGENT);

        if ($mine('User-Agent') && is_string($userAgent) && $userAgent !== '') {
            $lines[] = 'User-Agent: ' . $userAgent;
        }

        if ($mine('Accept')) {
            $lines[] = 'Accept: */*';
        }

        if ($mine('Accept-Encoding') && ($encoding = self::acceptEncoding($state->get(CURLOPT_ENCODING))) !== null) {
            $lines[] = 'Accept-Encoding: ' . $encoding;
        }

        if ($mine('Referer') && ($referer = self::referer($state, $redirects)) !== null) {
            $lines[] = 'Referer: ' . $referer;
        }

        $cookie = $state->get(CURLOPT_COOKIE);

        if ($mine('Cookie') && is_string($cookie) && $cookie !== '' && !self::cookieJarMayAdd($state, $redirects)) {
            $lines[] = 'Cookie: ' . $cookie;
        }

        // For an array body curl appends its own random boundary to the
        // application's Content-Type, so the line it sent is not the one
        // given, and it is left out like the rest of the multipart headers.
        $multipart = $state->bodySource() === 'multipart';

        foreach ($custom as $line) {
            if (stripos($line, 'host:') !== 0 && !($multipart && stripos($line, 'content-type:') === 0)) {
                $lines[] = $line;
            }
        }

        // What a redirect did to the body depends on the status it answered
        // with (a 302 turns a POST into a GET, a 307 keeps it), which is not
        // on record, so body headers are only rebuilt for a request that was
        // not redirected.
        if ($redirects === 0) {
            $length = self::contentLength($state);

            if ($length !== null && $mine('Content-Length') && $mine('Transfer-Encoding')) {
                $lines[] = 'Content-Length: ' . $length;
            }

            if ($mine('Content-Type') && $state->sentPostString() !== null) {
                $lines[] = 'Content-Type: application/x-www-form-urlencoded';
            }
        }

        return $lines;
    }

    /**
     * The application's header lines as curl sends them, and every name it
     * mentioned, removals included.
     *
     * @return array{list<string>, array<string, true>}
     */
    private static function custom(mixed $headers): array
    {
        if (!is_array($headers)) {
            return [[], []];
        }

        $lines = [];
        $named = [];

        foreach ($headers as $header) {
            if (!is_string($header)) {
                continue;
            }

            // `Name;` sends the header with an empty value.
            if (preg_match('/^([^:;\s]+)\s*;$/', $header, $m) === 1) {
                $named[strtolower($m[1])] = true;
                $lines[] = $m[1] . ':';

                continue;
            }

            if (preg_match('/^([^:\s]+):(.*)$/s', $header, $m) !== 1) {
                continue;
            }

            $named[strtolower($m[1])] = true;

            // `Name:` with nothing after it removes the header.
            if (trim($m[2]) !== '') {
                $lines[] = $header;
            }
        }

        return [$lines, $named];
    }

    /**
     * @param list<string> $custom
     */
    private static function customHost(array $custom): ?string
    {
        foreach ($custom as $line) {
            if (stripos($line, 'host:') === 0) {
                return $line;
            }
        }

        return null;
    }

    private static function host(HandleState $state, string $url): ?string
    {
        $parts = parse_url($url);

        if (!is_array($parts) || !isset($parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme'] ?? 'http');
        $option = $state->get(CURLOPT_PORT);
        $port = is_int($option) && $option > 0 ? $option : ($parts['port'] ?? null);
        $default = ['http' => 80, 'https' => 443][$scheme] ?? null;

        return $port === null || $port === $default
            ? $parts['host']
            : $parts['host'] . ':' . $port;
    }

    private static function authorization(HandleState $state, string $effectiveUrl, int $redirects): ?string
    {
        $scheme = $state->get(CURLOPT_HTTPAUTH);
        $scheme = $scheme === null ? CURLAUTH_BASIC : (is_int($scheme) ? $scheme : null);

        // curl drops credentials when a redirect moves to another host, unless
        // told not to.
        if ($redirects > 0
            && !HandleState::curlBool($state->get(CURLOPT_UNRESTRICTED_AUTH))
            && !self::sameOrigin((string) $state->url(), $effectiveUrl)) {
            return null;
        }

        if ($scheme === CURLAUTH_BEARER) {
            $token = $state->get(CURLOPT_XOAUTH2_BEARER);

            return is_string($token) && $token !== '' ? 'Bearer ' . $token : null;
        }

        // Anything but Basic alone either takes a challenge first (so the
        // request on record may have carried nothing, or a Digest response
        // computed from a nonce) or is not knowable from the options at all.
        if ($scheme !== CURLAUTH_BASIC) {
            return null;
        }

        $credentials = self::credentials($state);

        return $credentials === null ? null : 'Basic ' . base64_encode($credentials);
    }

    /**
     * user:password as curl will send it: the options win over credentials in
     * the URL, and a user name on its own is sent with an empty password.
     *
     * A password with no user name is sent by recent libcurl (8.22 sends
     * `:password`) and not by older builds, so it is left out.
     */
    private static function credentials(HandleState $state): ?string
    {
        $user = $state->get(CURLOPT_USERNAME);
        $password = $state->get(CURLOPT_PASSWORD);

        if (is_string($user)) {
            return $user . ':' . (is_string($password) ? $password : '');
        }

        if (is_string($password)) {
            return null;
        }

        $parts = parse_url((string) $state->url());

        if (!is_array($parts) || !isset($parts['user'])) {
            return null;
        }

        return rawurldecode($parts['user']) . ':' . rawurldecode($parts['pass'] ?? '');
    }

    private static function sameOrigin(string $a, string $b): bool
    {
        $origin = static function (string $url): ?string {
            $parts = parse_url($url);

            if (!is_array($parts) || !isset($parts['host'])) {
                return null;
            }

            $scheme = strtolower($parts['scheme'] ?? 'http');

            return $scheme . '://' . strtolower($parts['host']) . ':' . ($parts['port'] ?? (['http' => 80, 'https' => 443][$scheme] ?? ''));
        };

        return $origin($a) !== null && $origin($a) === $origin($b);
    }

    /**
     * An empty string asks for every encoding this libcurl can decode, in
     * the order it lists them.
     */
    private static function acceptEncoding(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        if ($value !== '') {
            return $value;
        }

        $features = (int) (curl_version()['features'] ?? 0);
        $encodings = [];

        if (($features & CURL_VERSION_LIBZ) !== 0) {
            $encodings[] = 'deflate';
            $encodings[] = 'gzip';
        }

        if (defined('CURL_VERSION_BROTLI') && ($features & CURL_VERSION_BROTLI) !== 0) {
            $encodings[] = 'br';
        }

        if (defined('CURL_VERSION_ZSTD') && ($features & CURL_VERSION_ZSTD) !== 0) {
            $encodings[] = 'zstd';
        }

        return $encodings === [] ? null : implode(', ', $encodings);
    }

    private static function referer(HandleState $state, int $redirects): ?string
    {
        // With AUTOREFERER, curl sends the URL it was redirected from. For one
        // hop that is the original URL, without credentials or fragment;
        // beyond one, the intermediate URLs are not on record.
        if ($redirects > 0 && HandleState::curlBool($state->get(CURLOPT_AUTOREFERER))) {
            if ($redirects > 1) {
                return null;
            }

            $parts = parse_url((string) $state->url());

            if (!is_array($parts) || !isset($parts['host'])) {
                return null;
            }

            return ($parts['scheme'] ?? 'http') . '://' . $parts['host']
                . (isset($parts['port']) ? ':' . $parts['port'] : '')
                . ($parts['path'] ?? '/')
                . (isset($parts['query']) ? '?' . $parts['query'] : '');
        }

        $referer = $state->get(CURLOPT_REFERER);

        return is_string($referer) && $referer !== '' ? $referer : null;
    }

    /**
     * Whether curl's cookie engine may have added cookies of its own, which
     * it merges into the same header. A shared handle, a cookie file or list,
     * or a redirect that could have set one: none of those are on record.
     */
    private static function cookieJarMayAdd(HandleState $state, int $redirects): bool
    {
        $file = $state->get(CURLOPT_COOKIEFILE);

        if ($state->has(CURLOPT_SHARE) || $state->has(CURLOPT_COOKIELIST)) {
            return true;
        }

        if (is_string($file) && $file !== '') {
            return true;
        }

        $engine = $state->has(CURLOPT_COOKIEFILE) || $state->has(CURLOPT_COOKIEJAR);

        return $engine && $redirects > 0;
    }

    /**
     * The body length curl declares, where the options fix it.
     */
    private static function contentLength(HandleState $state): ?int
    {
        $body = $state->sentPostString();

        if ($body !== null) {
            return strlen($body);
        }

        // A PUT reads its body from the callback and declares INFILESIZE. A
        // POST reading from one is sent chunked, and an array body as
        // multipart, whose boundary curl makes up.
        $size = $state->get(CURLOPT_INFILESIZE);

        if ($state->bodySource() === 'read' && $state->method() === 'PUT' && is_int($size) && $size >= 0) {
            return $size;
        }

        return null;
    }
}
