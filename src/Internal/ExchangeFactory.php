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
 *   request headers   what curl sent, where it told us, otherwise rebuilt
 *                     from the shadowed options (see RequestHeaders)
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
     * Cancelled, timed out, never started or finished unread: without
     * curl_multi_info_read there is no telling which.
     */
    public const UNREPORTED = 'removed before curl reported it complete; outcome unknown';

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
     * @param bool                 $reported whether curl reported how the
     *                                       transfer ended. A multi transfer
     *                                       removed before curl_multi_info_read
     *                                       said so may have been cancelled,
     *                                       timed out or never started, and
     *                                       curl_errno() cannot tell which.
     */
    public function create(
        HandleState $state,
        array $info,
        mixed $result,
        int $errno = 0,
        string $error = '',
        bool $reported = true,
    ): Exchange {
        $effectiveUrl = is_string($info['url'] ?? null) ? $info['url'] : ($state->url() ?? '');
        $sent = $this->sentRequestHeaders($info);
        $redirects = is_int($info['redirect_count'] ?? null) ? $info['redirect_count'] : 0;

        return new Exchange(
            id: Ulid::generate($state->startedAt() ?: null),
            correlationId: $state->correlationId() ?? Correlation::id(),
            transport: Exchange::TRANSPORT_CURL,
            method: $state->method(),
            uri: $effectiveUrl,
            requestHeaders: $sent ?? Headers::fromRaw(implode("\r\n", RequestHeaders::reconstruct($state, $effectiveUrl, $redirects))),
            requestBody: $this->requestBody($state),
            status: $this->status($info),
            reason: null,
            responseHeaders: Headers::fromRaw($state->finalResponseHeaderBlock()),
            // Whatever arrived before it was removed is a prefix at best, and
            // must not pass for the response.
            responseBody: $reported
                ? $this->responseBody($state, $result)
                : CapturedBody::omitted(CapturedBody::OMITTED_NOT_READABLE),
            timings: Timings::fromCurlInfo($info),
            error: $this->error($errno, $error, $reported),
            startedAt: $state->startedAt(),
            sequence: $state->sequence() ?? Correlation::nextSequence(),
            pid: getmypid() ?: null,
            // Says which it is. A rebuilt set leaves out whatever the options
            // do not determine (Digest, a multipart boundary, curl's cookie
            // jar), so it must not pass for the bytes on the wire.
            context: ['request_headers' => $sent === null ? 'reconstructed' : 'sent'],
        );
    }

    private function error(int $errno, string $error, bool $reported): ?TransferError
    {
        if ($errno !== 0) {
            return new TransferError($errno, $error !== '' ? $error : 'curl error ' . $errno);
        }

        // Not a success: nothing says it was one. -1, as for any failure that
        // is not a curl error code.
        if (!$reported) {
            return new TransferError(-1, self::UNREPORTED);
        }

        return null;
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
     * What libcurl actually sent, when the application asked curl to keep it.
     *
     * curl_getinfo() only carries request_header when CURLINFO_HEADER_OUT is
     * on, and we never turn it on ourselves, so its presence means the
     * application did and already has these bytes.
     *
     * @param array<string, mixed> $info
     */
    private function sentRequestHeaders(array $info): ?Headers
    {
        $sent = $info['request_header'] ?? null;

        return is_string($sent) && $sent !== '' ? Headers::fromRaw($sent) : null;
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

        $contentType = Headers::fromRaw($state->finalResponseHeaderBlock())->first('Content-Type');

        // A missing Content-Type normally means the server sent none, and core
        // captures the body on the assumption it is text. That assumption does
        // not hold when we know headers were dropped for size: the type may
        // have been among them, and guessing wrong stores a binary payload the
        // content-type gate exists to keep out.
        if ($contentType === null && $state->headersTruncated()) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_NOT_READABLE,
                strlen($result),
            );
        }

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


}
