<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

/**
 * A shadow copy of one curl handle's options.
 *
 * curl options are write-only. There is no `curl_getopt()`, so a handle cannot
 * be asked what its URL, POSTFIELDS or HTTPHEADER are. The only way to know is
 * to watch every `curl_setopt()` call go past and keep a parallel record.
 * Datadog's tracer does the same thing; there is no cleverer approach
 * available.
 */
final class HandleState
{
    /** @var array<int, mixed> */
    private array $options = [];

    /**
     * Completed header blocks from earlier hops in a redirect chain.
     */
    private string $responseHeaderBuffer = '';

    /**
     * The block for the response currently arriving, kept separately so a
     * long redirect chain cannot starve it.
     */
    private string $currentHeaderBlock = '';

    private bool $headersTruncated = false;

    private float $startedAt = 0.0;

    private bool $capturing = false;

    private bool $headersInstalled = false;

    /**
     * Set when the shadow state is known to disagree with the handle.
     */
    private ?string $unsafeReason = null;

    private const MAX_HEADER_BLOCK_BYTES = 65536;

    private const MAX_HEADER_CHAIN_BYTES = 262144;

    /** @var callable|null */
    private $appHeaderFunction = null;

    public function set(int $option, mixed $value): void
    {
        $this->options[$option] = $value;

        // Remember the application's own header callback so ours can chain
        // onto it rather than silently replacing it.
        if ($option === CURLOPT_HEADERFUNCTION) {
            $this->appHeaderFunction = is_callable($value) ? $value : null;

            // The application replaced the callback on a reused handle, which
            // removed our wrapper. Without this, headersInstalled stayed true
            // and every later response on that handle was recorded with no
            // headers at all — and a body with no content type slips past the
            // redactor's binary gate.
            $this->headersInstalled = false;
        }

        // curl treats these as mutually exclusive method switches. Tracking
        // only the last-set option reported POST with a stale body after the
        // caller switched back to GET.
        if ($option === CURLOPT_HTTPGET && self::curlBool($value)) {
            // NOBODY too. CURLOPT_HTTPGET clears it in curl, so a handle
            // switched from HEAD back to GET was sending GET while the record
            // said HEAD — and a HEAD record carries no response body, so the
            // body of that GET was reported as absent rather than captured.
            unset(
                $this->options[CURLOPT_POST],
                $this->options[CURLOPT_POSTFIELDS],
                $this->options[CURLOPT_PUT],
                $this->options[CURLOPT_NOBODY],
            );
        }

        if ($option === CURLOPT_POST && self::curlBool($value)) {
            unset($this->options[CURLOPT_HTTPGET], $this->options[CURLOPT_NOBODY]);
        }
    }

    /**
     * @param array<int, mixed> $options
     */
    public function setMany(array $options): void
    {
        foreach ($options as $option => $value) {
            $this->set($option, $value);
        }
    }

    public function get(int $option): mixed
    {
        return $this->options[$option] ?? null;
    }

    public function has(int $option): bool
    {
        return array_key_exists($option, $this->options);
    }

    public function url(): ?string
    {
        $url = $this->options[CURLOPT_URL] ?? null;

        return is_string($url) ? $url : null;
    }

    public function method(): string
    {
        if (isset($this->options[CURLOPT_CUSTOMREQUEST]) && is_string($this->options[CURLOPT_CUSTOMREQUEST])) {
            // Exactly as given. curl sends a custom method verbatim, and
            // upper-casing it meant the record disagreed with the request —
            // WebDAV and several vendor APIs use mixed-case verbs.
            return $this->options[CURLOPT_CUSTOMREQUEST];
        }

        // curl accepts 1 as well as true. A strict === true check reported
        // GET for `curl_setopt($ch, CURLOPT_POST, 1)`, which is the form most
        // code in the wild uses.
        if ($this->isOn(CURLOPT_NOBODY)) {
            return 'HEAD';
        }

        if ($this->isOn(CURLOPT_POST) || isset($this->options[CURLOPT_POSTFIELDS])) {
            return 'POST';
        }

        if ($this->isOn(CURLOPT_PUT)) {
            return 'PUT';
        }

        return 'GET';
    }

    /**
     * The request body, where it was supplied as a string or an array.
     *
     * A CURLFile or a read callback is not reconstructible — what was
     * configured is not always what was transmitted — so those report null and
     * the exchange records an omission rather than a guess.
     */
    private function isOn(int $option): bool
    {
        return self::curlBool($this->options[$option] ?? false);
    }

    /**
     * Whether curl would treat this value as on.
     *
     * PHP converts the value for a boolean curl option with its ordinary
     * integer cast and libcurl treats any non-zero as on, so `2`, `'2'` and
     * `1.0` all enable an option while `'yes'` does not. Verified against
     * ext-curl for CURLOPT_HEADER and CURLOPT_VERBOSE rather than assumed.
     *
     * Recognising only true, 1 and '1' meant `CURLOPT_HEADER => 2` looked off:
     * with RETURNTRANSFER the response headers were then recorded as body
     * text, where header redaction never looks, and an intermediate redirect's
     * Set-Cookie survived into the record.
     */
    public static function curlBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (int) $value !== 0;
        }

        if (is_string($value)) {
            return (int) $value !== 0;
        }

        return false;
    }

    /**
     * The content type of the request body as curl will actually send it.
     *
     * An array of POSTFIELDS without an explicit Content-Type is sent as
     * multipart. Reporting a null content type made the redactor try JSON
     * parsing on a form-encoded reconstruction, so configured body-path rules
     * did nothing at all.
     */
    public function requestContentType(): ?string
    {
        foreach ($this->requestHeaderLines() as $line) {
            if (stripos($line, 'content-type:') === 0) {
                return trim(substr($line, 13));
            }
        }

        $fields = $this->options[CURLOPT_POSTFIELDS] ?? null;

        if (is_array($fields)) {
            return 'application/x-www-form-urlencoded';
        }

        // A string POSTFIELDS with no explicit header is what curl sends as
        // application/x-www-form-urlencoded. Reporting null made the redactor
        // try to parse it as JSON, and with bodyPaths configured that failed
        // to inspect the body and dropped the whole thing — so a form post
        // that could have been recorded with one field redacted was recorded
        // as nothing at all.
        if (is_string($fields)) {
            return 'application/x-www-form-urlencoded';
        }

        return null;
    }

    /**
     * CURLOPT_HEADER makes curl_exec() return the response headers prepended
     * to the body. Treating that whole string as the body embedded unredacted
     * headers — including Set-Cookie from intermediate redirects — inside the
     * recorded body, where header redaction never looks.
     */
    public function returnsHeadersInBody(): bool
    {
        return $this->isOn(CURLOPT_HEADER);
    }

    public function requestBody(): ?string
    {
        $fields = $this->options[CURLOPT_POSTFIELDS] ?? null;

        if (is_string($fields)) {
            return $fields;
        }

        if (is_array($fields)) {
            foreach ($fields as $value) {
                if ($value instanceof \CURLFile || $value instanceof \CURLStringFile) {
                    return null;
                }
            }

            return http_build_query($fields);
        }

        return null;
    }

    public function requestBodyIsUnreconstructible(): bool
    {
        $fields = $this->options[CURLOPT_POSTFIELDS] ?? null;

        if ($fields === null) {
            return isset($this->options[CURLOPT_READFUNCTION])
                || isset($this->options[CURLOPT_INFILE]);
        }

        return !is_string($fields) && $this->requestBody() === null;
    }

    /**
     * Headers the application set explicitly.
     *
     * These are not the headers actually sent — libcurl adds its own, and
     * CURLINFO_HEADER_OUT is what reports the real set. This is the fallback
     * for when HEADER_OUT is unavailable because the application turned on
     * CURLOPT_VERBOSE.
     *
     * @return list<string>
     */
    public function requestHeaderLines(): array
    {
        $headers = $this->options[CURLOPT_HTTPHEADER] ?? null;

        if (!is_array($headers)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn (mixed $h): string => is_string($h) ? $h : '', $headers),
            static fn (string $h): bool => $h !== '',
        ));
    }

    /**
     * CURLINFO_HEADER_OUT and CURLOPT_VERBOSE occupy the same libcurl debug
     * slot: setting one silently blanks the other, with no warning and no
     * error. If the application asked for verbose output, that is theirs and
     * we do not take it away.
     */
    public function canUseHeaderOut(): bool
    {
        // `CURLOPT_VERBOSE => 1` is the form most code uses. A strict !== true
        // check read it as off, so wiretap installed CURLINFO_HEADER_OUT into
        // the same libcurl debug slot and the application's verbose output
        // silently stopped — diagnostics it had explicitly asked for.
        return !$this->isOn(CURLOPT_VERBOSE);
    }

    public function returnsTransfer(): bool
    {
        return $this->isOn(CURLOPT_RETURNTRANSFER);
    }

    public function isStreamingToCallback(): bool
    {
        return isset($this->options[CURLOPT_WRITEFUNCTION])
            || isset($this->options[CURLOPT_FILE]);
    }

    public function appHeaderFunction(): ?callable
    {
        return $this->appHeaderFunction;
    }

    /**
     * The stream curl would write response headers to.
     *
     * An application can route headers to a file without ever setting a
     * callback, using CURLOPT_WRITEHEADER alone. Installing our own
     * HEADERFUNCTION takes that destination over, and the file it was writing
     * to stayed empty — instrumentation changing what the application does,
     * which is the one thing this package must never do. The wrapper writes
     * the bytes there itself instead.
     *
     * @return resource|null
     */
    public function appHeaderStream()
    {
        if ($this->appHeaderFunction !== null) {
            // A callback wins over WRITEHEADER in curl, so there is no
            // destination for us to stand in for.
            return null;
        }

        $stream = $this->options[CURLOPT_WRITEHEADER] ?? null;

        return is_resource($stream) ? $stream : null;
    }

    public function appendResponseHeader(string $line): void
    {
        // A status line starts a new response. Blocks were previously split on
        // blank lines, which made HTTP trailers look like a fresh response:
        // a chunked application/octet-stream followed by a trailer block left
        // the trailer as the recorded headers, the real Content-Type was lost,
        // and core then treated the binary body as capturable and stored it.
        if (self::isStatusLine($line) && $this->currentHeaderBlock !== '') {
            $this->archiveCurrentBlock();
        }

        // The current response's block is bounded on its own.
        //
        // One shared 64 KiB buffer meant a long redirect chain could exhaust
        // it before the final response even started, so its Content-Type was
        // discarded, the factory reported none, and the redactor kept a body
        // it would otherwise have dropped. The block that decides that is now
        // always the one with room.
        if (strlen($this->currentHeaderBlock) < self::MAX_HEADER_BLOCK_BYTES) {
            $this->currentHeaderBlock .= $line;

            return;
        }

        $this->headersTruncated = true;
    }

    private function archiveCurrentBlock(): void
    {
        if (strlen($this->responseHeaderBuffer) + strlen($this->currentHeaderBlock) <= self::MAX_HEADER_CHAIN_BYTES) {
            $this->responseHeaderBuffer .= $this->currentHeaderBlock;
        } else {
            // Earlier hops are what gets dropped, never the response the
            // caller actually received.
            $this->headersTruncated = true;
        }

        $this->currentHeaderBlock = '';
    }

    private static function isStatusLine(string $line): bool
    {
        return preg_match('#^HTTP/\d#i', $line) === 1;
    }

    /**
     * Every header block observed, including redirect hops.
     */
    public function responseHeaders(): string
    {
        return $this->responseHeaderBuffer . $this->currentHeaderBlock;
    }

    /**
     * The headers of the response the caller actually received.
     */
    public function finalResponseHeaderBlock(): string
    {
        return $this->currentHeaderBlock;
    }

    /**
     * Whether anything was dropped for size. A missing Content-Type cannot be
     * trusted to mean the server did not send one when this is true.
     */
    public function headersTruncated(): bool
    {
        return $this->headersTruncated;
    }

    public function beginTransfer(bool $capturing): void
    {
        $this->capturing = $capturing;
        $this->startedAt = microtime(true);
        $this->responseHeaderBuffer = '';
        $this->currentHeaderBlock = '';
        $this->headersTruncated = false;
    }

    public function isCapturing(): bool
    {
        return $this->capturing;
    }

    /**
     * Mark the transfer as recorded.
     *
     * A multi transfer can be reported complete twice — once by
     * curl_multi_info_read and again by curl_multi_remove_handle — and an
     * application is free to call either, both or neither. Clearing the flag
     * here is what makes recording happen exactly once per transfer however
     * the application drives the loop.
     */
    public function endTransfer(): void
    {
        $this->capturing = false;
    }

    public function startedAt(): float
    {
        return $this->startedAt;
    }

    public function markHeadersInstalled(): void
    {
        $this->headersInstalled = true;
    }

    public function headersInstalled(): bool
    {
        return $this->headersInstalled;
    }

    /**
     * curl_copy_handle() duplicates the options, so the shadow must be
     * duplicated too or the copy looks like a blank handle.
     */
    public function copy(): self
    {
        $copy = new self();
        $copy->options = $this->options;
        $copy->appHeaderFunction = $this->appHeaderFunction;

        return $copy;
    }

    /**
     * curl_reset() returns the handle to its default state.
     */
    public function reset(): void
    {
        $this->options = [];
        $this->appHeaderFunction = null;
        $this->responseHeaderBuffer = '';
        $this->currentHeaderBlock = '';
        $this->headersTruncated = false;
        $this->capturing = false;
        $this->headersInstalled = false;
        // curl_reset puts the handle back to defaults, which is the one thing
        // that can make a divergent shadow state agree again.
        $this->unsafeReason = null;
    }

    /**
     * Record that we no longer know what this handle is configured to do.
     *
     * curl exposes no way to read an option back, so the shadow state is the
     * only model we have. A curl_setopt_array() that fails part way through
     * applies some of its options and rejects the rest, and we cannot tell
     * which — so every capture decision taken from it is a guess. Guessing
     * wrong about CURLOPT_HEADER in particular writes the response headers
     * into the recorded body, where header redaction never looks.
     *
     * Capture is declined until curl_reset() re-establishes a known state.
     */
    public function markUnsafe(string $reason): void
    {
        $this->unsafeReason = $reason;
    }

    public function isUnsafe(): bool
    {
        return $this->unsafeReason !== null;
    }

    public function unsafeReason(): ?string
    {
        return $this->unsafeReason;
    }
}
