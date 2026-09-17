<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Support\Ulid;
use Ssx\Wiretap\Timings;
use Ssx\Wiretap\TransferError;

/**
 * Assembles an Exchange from the five sources a curl transfer exposes.
 *
 *   request headers   CURLINFO_HEADER_OUT, or the shadowed HTTPHEADER lines
 *   request body      the shadowed CURLOPT_POSTFIELDS
 *   response headers  our chained CURLOPT_HEADERFUNCTION
 *   response body     the curl_exec() return value
 *   timings, errno    curl_getinfo() and curl_errno()
 *
 * None of these is optional and none is obtainable after the fact, which is
 * why the whole handle lifecycle has to be observed rather than just the
 * execution.
 */
final readonly class ExchangeFactory
{
    /**
     * @param int $maxBodyBytes A hard memory ceiling, not the redaction limit.
     *
     * Capturing only 64 KiB here handed the redactor a truncated JSON body it
     * could not parse, so configured body-path rules silently did nothing.
     * Reading a larger bounded amount lets structural redaction run; the core
     * truncates to its own limit afterwards.
     */
    public function __construct(private int $maxBodyBytes = 1_048_576)
    {
    }

    /**
     * @param array<string, mixed> $info    curl_getinfo() output
     * @param mixed                $result  the curl_exec() return value
     */
    public function create(
        HandleState $state,
        array $info,
        mixed $result,
        int $errno = 0,
        string $error = '',
    ): Exchange {
        $effectiveUrl = is_string($info['url'] ?? null) ? $info['url'] : ($state->url() ?? '');

        return new Exchange(
            id: Ulid::generate($state->startedAt() ?: null),
            correlationId: Correlation::id(),
            transport: Exchange::TRANSPORT_CURL,
            method: $state->method(),
            uri: $effectiveUrl,
            requestHeaders: $this->requestHeaders($state, $info),
            requestBody: $this->requestBody($state),
            status: $this->status($info),
            reason: null,
            responseHeaders: Headers::fromRaw($this->lastResponseHeaderBlock($state->responseHeaders())),
            responseBody: $this->responseBody($state, $result),
            timings: Timings::fromCurlInfo($info),
            error: $errno !== 0
                ? new TransferError($errno, $error !== '' ? $error : 'curl error ' . $errno)
                : null,
            startedAt: $state->startedAt(),
            sequence: Correlation::nextSequence(),
            pid: getmypid() ?: null,
        );
    }

    /**
     * @param array<string, mixed> $info
     */
    private function status(array $info): ?int
    {
        $code = $info['http_code'] ?? null;

        return is_int($code) && $code > 0 ? $code : null;
    }

    /**
     * Prefer what libcurl actually sent. It adds headers of its own — Host,
     * Accept, Content-Length, any authentication — so the application's
     * HTTPHEADER list is only a fallback for when HEADER_OUT is unavailable.
     */
    /**
     * @param array<string, mixed> $info
     */
    private function requestHeaders(HandleState $state, array $info): Headers
    {
        $sent = $info['request_header'] ?? null;

        if (is_string($sent) && $sent !== '') {
            return Headers::fromRaw($sent);
        }

        return Headers::fromRaw(implode("\r\n", $state->requestHeaderLines()));
    }

    private function requestBody(HandleState $state): CapturedBody
    {
        if ($state->requestBodyIsUnreconstructible()) {
            // A CURLFile, or a read callback. What was configured is not what
            // was transmitted, and guessing would be worse than admitting it.
            return CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE);
        }

        $body = $state->requestBody();

        if ($body === null || $body === '') {
            return CapturedBody::none();
        }

        $contentType = $state->requestContentType();
        $size = strlen($body);

        if ($size > $this->maxBodyBytes) {
            return CapturedBody::captured(
                bytes: substr($body, 0, $this->maxBodyBytes),
                size: $size,
                contentType: $contentType,
                truncated: true,
                sha256: hash('sha256', $body),
            );
        }

        return CapturedBody::captured($body, $size, $contentType);
    }

    /**
     * The return value of curl_exec() is the response body, but only when
     * CURLOPT_RETURNTRANSFER was set. Without it the application is streaming
     * to stdout or a file handle and curl_exec() returns a bool.
     *
     * Forcing RETURNTRANSFER on to make capture easier would change where the
     * application's response goes. A missing body is a bug report; a corrupted
     * download is an incident.
     */
    private function responseBody(HandleState $state, mixed $result): CapturedBody
    {
        if (!is_string($result)) {
            return CapturedBody::omitted(
                $state->isStreamingToCallback()
                    ? CapturedBody::OMITTED_STREAMING
                    : CapturedBody::OMITTED_NOT_RETURNED,
            );
        }

        if ($result === '') {
            return CapturedBody::none();
        }

        // With CURLOPT_HEADER the return value is headers followed by the
        // body, and a redirect chain prepends one block per hop. Recording the
        // whole string as the body embedded unredacted headers — including
        // Set-Cookie from intermediate hops — where header redaction never
        // looks. Splitting it reliably across redirects and 1xx responses is
        // not something to guess at, so the body is omitted instead.
        if ($state->returnsHeadersInBody()) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_NOT_READABLE,
                strlen($result),
            );
        }

        $contentType = Headers::fromRaw($this->lastResponseHeaderBlock($state->responseHeaders()))
            ->first('Content-Type');

        $size = strlen($result);

        if ($size > $this->maxBodyBytes) {
            return CapturedBody::captured(
                bytes: substr($result, 0, $this->maxBodyBytes),
                size: $size,
                contentType: $contentType,
                truncated: true,
                sha256: hash('sha256', $result),
            );
        }

        return CapturedBody::captured($result, $size, $contentType);
    }

    /**
     * A redirect chain produces several header blocks separated by a blank
     * line. The last one describes the response the caller actually received.
     */
    private function lastResponseHeaderBlock(string $raw): string
    {
        $raw = trim($raw);

        if ($raw === '') {
            return '';
        }

        $blocks = preg_split("/(\r\n){2,}|\n{2,}/", $raw) ?: [$raw];
        $blocks = array_values(array_filter($blocks, static fn (string $b): bool => trim($b) !== ''));

        return $blocks === [] ? '' : (string) end($blocks);
    }

}
