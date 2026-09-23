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

    /**
     * The correlation and sequence the transfer started under. A multi
     * transfer can finish long after the unit of work that began it has
     * ended, so these are taken when it starts, not when it is recorded.
     */
    private ?string $correlationId = null;

    private ?int $sequence = null;

    /**
     * The multi handle this transfer runs on, and how far it had got when
     * the transfer joined it. Null for curl_exec().
     */
    private ?MultiProgress $multi = null;

    private int $addedAtExec = 0;

    private bool $capturing = false;

    private bool $headersInstalled = false;

    /**
     * Set when the shadow state is known to disagree with the handle.
     */
    private ?string $unsafeReason = null;

    /**
     * A bridge recording this transfer itself has claimed the handle.
     */
    private bool $claimed = false;

    private const MAX_HEADER_BLOCK_BYTES = 65536;

    private const MAX_HEADER_CHAIN_BYTES = 262144;

    /**
     * The application's own header callback, held weakly. See CallbackRef.
     */
    private ?CallbackRef $appHeaderFunction = null;

    /**
     * Where curl sends response headers: 'callback', 'file' or null.
     *
     * In ext-curl CURLOPT_HEADERFUNCTION and CURLOPT_WRITEHEADER each switch
     * the header handler to themselves, so whichever was set last wins. This
     * was modelled as the callback always winning, which had curl writing to
     * the file while wiretap called the callback.
     */
    private ?string $headerTarget = null;

    /**
     * libcurl's method state, which every method option moves (measured
     * against libcurl 8): GET, POST (a string body or a read callback),
     * POST_MIME (an array body, sent as multipart), PUT or HEAD.
     */
    private string $httpRequest = 'GET';

    /**
     * CURLOPT_NOBODY. Separate from the method: a string POSTFIELDS set after
     * it leaves it on, so the request is still HEAD.
     */
    private bool $noBody = false;

    /**
     * The last string body and the last array body. libcurl keeps both, and
     * which one is sent depends on the method at the time of the transfer: a
     * string body survives a switch to GET and is sent again by a later
     * POST=true, and an array body is not sent by POST=true at all.
     */
    private ?string $postString = null;

    /** @var array<array-key, mixed>|true|null true when it holds something unreadable */
    private array|bool|null $postMime = null;

    /**
     * The boundary a rebuilt multipart body uses. curl picks a random one per
     * request, 24 dashes and 22 characters in libcurl 8; this has the same
     * length, so the rebuilt body is the size of the one sent.
     */
    public const MULTIPART_BOUNDARY = '------------------------wiretapreconstructed00';

    public function set(int $option, mixed $value): void
    {
        // Callbacks and other objects are recorded as present, never held.
        // This state is a WeakMap value keyed by the handle, and on PHP 8.2 a
        // value that leads back to its key keeps both alive for good. Every
        // question asked of these options is whether one is set, so nothing
        // is lost by not keeping the object itself.
        $this->options[$option] = self::shadowValue($value);

        // CURLOPT_USERPWD sets both halves; CURLOPT_USERNAME and
        // CURLOPT_PASSWORD each set one, and whichever came last wins. Kept
        // as the two halves so the rebuilt Authorization follows the same
        // order curl does.
        if ($option === CURLOPT_USERPWD) {
            unset($this->options[CURLOPT_USERPWD]);

            if (is_string($value)) {
                [$user, $password] = explode(':', $value, 2) + [1 => ''];
                $this->options[CURLOPT_USERNAME] = $user;
                $this->options[CURLOPT_PASSWORD] = $password;
            } else {
                unset($this->options[CURLOPT_USERNAME], $this->options[CURLOPT_PASSWORD]);
            }
        }

        // ext-curl sends a Stringable header as its string. We cannot read it
        // without calling application code, and a header list recorded
        // without it is not what was sent — dropping Content-Type made a
        // JSON body look form-encoded, so bodyPaths redaction missed its
        // keys. Decline instead of guessing.
        if ($option === CURLOPT_HTTPHEADER && is_array($value)) {
            foreach ($value as $header) {
                if (!is_string($header)) {
                    $this->markUnsafe('CURLOPT_HTTPHEADER holds a value that is not a string');

                    break;
                }
            }
        }

        // Remember the application's own header callback so ours can chain
        // onto it rather than silently replacing it.
        if ($option === CURLOPT_HEADERFUNCTION) {
            $this->appHeaderFunction = $value === null ? null : CallbackRef::of($value);
            $this->headerTarget = $value === null ? null : 'callback';

            // The application replaced the callback on a reused handle, which
            // removed our wrapper. Without this, headersInstalled stayed true
            // and every later response on that handle was recorded with no
            // headers at all — and a body with no content type slips past the
            // redactor's binary gate.
            $this->headersInstalled = false;
        }

        // Setting it, to a stream or to null, moves curl's header handler off
        // our wrapper just as replacing the callback does. Without this the
        // next response on the handle was recorded with no headers at all.
        if ($option === CURLOPT_WRITEHEADER) {
            $this->headerTarget = is_resource($value) ? 'file' : null;
            $this->headersInstalled = false;
        }

        $this->moveMethod($option, $value);
    }

    /**
     * libcurl's method state machine, as measured against what a server
     * receives. Modelling each option on its own recorded a POST the server
     * saw as a GET after POST=false or NOBODY 1 then 0, and a GET for UPLOAD.
     */
    private function moveMethod(int $option, mixed $value): void
    {
        switch ($option) {
            case CURLOPT_POSTFIELDS:
                // ext-curl sends a non-empty array or an object as multipart
                // (CURLOPT_MIMEPOST, which also clears NOBODY), and anything
                // else as a string (COPYPOSTFIELDS, which does not): null and
                // an empty array become an empty body.
                if (is_object($value) || (is_array($value) && $value !== [])) {
                    $shadow = self::shadowValue($value);
                    $this->postMime = is_array($shadow) ? $shadow : true;
                    $this->httpRequest = 'POST_MIME';
                    $this->noBody = false;
                } else {
                    $this->postString = is_scalar($value) ? (string) $value : '';
                    $this->httpRequest = 'POST';
                }

                break;

            case CURLOPT_POST:
                if (self::curlBool($value)) {
                    $this->httpRequest = 'POST';
                    $this->noBody = false;
                } else {
                    $this->httpRequest = 'GET';
                }

                break;

            case CURLOPT_HTTPGET:
                if (self::curlBool($value)) {
                    $this->httpRequest = 'GET';
                    $this->noBody = false;
                }

                break;

            case CURLOPT_NOBODY:
                $this->noBody = self::curlBool($value);

                if ($this->noBody) {
                    $this->httpRequest = 'HEAD';
                } elseif ($this->httpRequest === 'HEAD') {
                    $this->httpRequest = 'GET';
                }

                break;

            case CURLOPT_UPLOAD:
            case CURLOPT_PUT:
                if (self::curlBool($value)) {
                    $this->httpRequest = 'PUT';
                    $this->noBody = false;
                } else {
                    $this->httpRequest = 'GET';
                }

                break;
        }
    }

    /**
     * What to keep of an option value.
     *
     * An object, or an array holding one, becomes `true`: set, and on as far
     * as curl's integer conversion is concerned, which is what ext-curl does
     * with it too. A POSTFIELDS array holding a CURLFile therefore reads as
     * a body we cannot reconstruct, which is the answer it always got.
     */
    private static function shadowValue(mixed $value): mixed
    {
        if (is_object($value)) {
            return true;
        }

        if (is_array($value)) {
            $objects = false;

            array_walk_recursive($value, static function (mixed $item) use (&$objects): void {
                $objects = $objects || is_object($item);
            });

            return $objects ? true : $value;
        }

        return $value;
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

        if ($this->noBody) {
            return 'HEAD';
        }

        return $this->httpRequest === 'POST_MIME' ? 'POST' : $this->httpRequest;
    }

    /**
     * What curl sends as the request body: nothing, the string body, the
     * array body as multipart, or whatever a read callback or INFILE gives it.
     *
     * The method name does not decide this. A custom GET sends the string
     * body; a custom PATCH after POST=false sends nothing.
     *
     * @return 'none'|'string'|'multipart'|'read'
     */
    public function bodySource(): string
    {
        if ($this->noBody) {
            return 'none';
        }

        return match ($this->httpRequest) {
            'POST' => $this->postString !== null ? 'string' : 'read',
            'POST_MIME' => 'multipart',
            'PUT' => 'read',
            default => 'none',
        };
    }

    /**
     * The string body, when that is what curl sends.
     */
    public function sentPostString(): ?string
    {
        return $this->bodySource() === 'string' ? $this->postString : null;
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

        // The same cast gives 1 for a non-empty array and for a resource.
        // Reading `CURLOPT_HEADER => [1]` as off put the response headers in
        // the recorded body. Objects are shadowed as `true` before this.
        if (is_array($value)) {
            return $value !== [];
        }

        return is_resource($value);
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
        $source = $this->bodySource();
        $explicit = $this->explicitContentType();

        // curl sends an array body as multipart, whose boundary it makes up
        // and appends to the type. The rebuilt body uses its own boundary, so
        // the type on record is the one that describes the stored bytes.
        // Reporting it as a form made the record claim a body that was never
        // sent.
        if ($source === 'multipart') {
            return $explicit === null || self::isFormData($explicit)
                ? 'multipart/form-data; boundary=' . self::MULTIPART_BOUNDARY
                : $explicit;
        }

        if ($explicit !== null) {
            return $explicit;
        }

        // A string POSTFIELDS with no explicit header is what curl sends as
        // application/x-www-form-urlencoded. Reporting null made the redactor
        // try to parse it as JSON, and with bodyPaths configured that failed
        // to inspect the body and dropped the whole thing — so a form post
        // that could have been recorded with one field redacted was recorded
        // as nothing at all.
        if ($source === 'string' || ($source === 'read' && $this->httpRequest === 'POST')) {
            return 'application/x-www-form-urlencoded';
        }

        return null;
    }

    private function explicitContentType(): ?string
    {
        foreach ($this->requestHeaderLines() as $line) {
            if (stripos($line, 'content-type:') === 0) {
                return trim(substr($line, 13));
            }
        }

        return null;
    }

    private static function isFormData(string $type): bool
    {
        return strtolower(trim(explode(';', $type)[0])) === 'multipart/form-data';
    }

    /**
     * Whether the recorded request body is rebuilt rather than the bytes sent.
     */
    public function requestBodyIsRebuilt(): bool
    {
        return $this->bodySource() === 'multipart' && $this->requestBody() !== null;
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

    /**
     * The request body curl sends, where the options determine it.
     */
    public function requestBody(): ?string
    {
        return match ($this->bodySource()) {
            'string' => $this->postString,
            'multipart' => $this->multipartBody(),
            default => null,
        };
    }

    public function requestBodyIsUnreconstructible(): bool
    {
        return match ($this->bodySource()) {
            'read' => isset($this->options[CURLOPT_READFUNCTION]) || isset($this->options[CURLOPT_INFILE]),
            'multipart' => $this->requestBody() === null,
            default => false,
        };
    }

    /**
     * The array body as curl writes it, with our boundary in place of its
     * random one: one form-data part per field, the name with `"`, CR and LF
     * percent-encoded, the value as PHP casts it to a string. Measured
     * against the bytes a server received.
     *
     * Null where that is not what curl sends: a CURLFile or other object
     * (recorded as `true`), a nested array, a name curl would cut at a NUL
     * byte, or a Content-Type the application set to something other than
     * form-data, under which curl lays the parts out differently.
     */
    private function multipartBody(): ?string
    {
        $explicit = $this->explicitContentType();

        if (!is_array($this->postMime) || ($explicit !== null && !self::isFormData($explicit))) {
            return null;
        }

        $delimiter = '--' . self::MULTIPART_BOUNDARY;
        $body = '';

        foreach ($this->postMime as $name => $value) {
            $name = (string) $name;

            if (is_array($value) || str_contains($name, "\0")) {
                return null;
            }

            $body .= $delimiter . "\r\n"
                . 'Content-Disposition: form-data; name="' . strtr($name, ['"' => '%22', "\r" => '%0D', "\n" => '%0A']) . "\"\r\n"
                . "\r\n"
                . (is_scalar($value) ? (string) $value : '') . "\r\n";
        }

        return $body . $delimiter . "--\r\n";
    }

    /**
     * Headers the application set explicitly, as curl sends them.
     *
     * These are not every header sent — libcurl adds its own, such as Host
     * and Accept. Only CURLINFO_HEADER_OUT reports the full set, and turning
     * that on ourselves put the plaintext request headers, Authorization
     * included, into the application's own curl_getinfo(), from where Guzzle
     * copies them into handler stats and exception context. So this is the
     * record unless the application turned HEADER_OUT on itself.
     *
     * `Name:` with no value tells curl to remove a header it would have
     * added, so nothing by that name is sent; `Name;` sends it empty.
     *
     * @return list<string>
     */
    public function requestHeaderLines(): array
    {
        $headers = $this->options[CURLOPT_HTTPHEADER] ?? null;

        if (!is_array($headers)) {
            return [];
        }

        $lines = [];

        foreach ($headers as $header) {
            if (!is_string($header) || $header === '') {
                continue;
            }

            if (preg_match('/^([^:;\s]+)\s*;$/', $header, $m) === 1) {
                $lines[] = $m[1] . ':';

                continue;
            }

            // A removal, or a line curl does not send at all: no name, or no
            // colon (`X-C`, `X-E;foo`, `X-A; `). Measured against what curl
            // reports through CURLINFO_HEADER_OUT.
            if (preg_match('/^[^:]+:\s*$/', $header) === 1 || preg_match('/^[^:\s]+:/', $header) !== 1) {
                continue;
            }

            $lines[] = $header;
        }

        return $lines;
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

    /**
     * Whether the application set a header callback of its own.
     */
    public function hasAppHeaderFunction(): bool
    {
        return $this->headerTarget === 'callback' && $this->appHeaderFunction !== null;
    }

    /**
     * The application's header callback as it gave it, or null if it has
     * none or it can no longer be rebuilt. Callability is for the caller to
     * judge from its own scope.
     */
    public function appHeaderFunction(): mixed
    {
        return $this->headerTarget === 'callback' ? $this->appHeaderFunction?->resolve() : null;
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
        if ($this->headerTarget !== 'file') {
            // A callback set after it wins over WRITEHEADER in curl, so there
            // is no destination for us to stand in for.
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

    public function beginTransfer(bool $capturing, ?string $correlationId = null, ?int $sequence = null): void
    {
        $this->capturing = $capturing;
        $this->correlationId = $correlationId;
        $this->sequence = $sequence;
        $this->multi = null;
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

    public function joinMulti(MultiProgress $multi): void
    {
        $this->multi = $multi;
        $this->addedAtExec = $multi->execs();
    }

    /**
     * Where the multi transfer had got, as far as curl_multi_exec() said.
     *
     * @return 'unstarted'|'running'|'finished'|null null when not on a multi handle
     */
    public function multiPhase(): ?string
    {
        return $this->multi?->phaseOf($this->addedAtExec);
    }

    public function correlationId(): ?string
    {
        return $this->correlationId;
    }

    public function sequence(): ?int
    {
        return $this->sequence;
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
     *
     * That includes what we know we do not know. A copy of a handle whose
     * options are unknown has the same unknown options, and dropping the mark
     * let a copy of a half-applied curl_setopt_array() be captured with its
     * response headers inside the body.
     *
     * curl copies our header wrapper to the copy as well. It works out whose
     * transfer a line belongs to from the handle curl passes it, so it is as
     * installed on the copy as on the source.
     */
    public function copy(): self
    {
        $copy = new self();
        $copy->options = $this->options;
        $copy->appHeaderFunction = $this->appHeaderFunction;
        $copy->headerTarget = $this->headerTarget;
        $copy->headersInstalled = $this->headersInstalled;
        $copy->unsafeReason = $this->unsafeReason;
        $copy->httpRequest = $this->httpRequest;
        $copy->noBody = $this->noBody;
        $copy->postString = $this->postString;
        $copy->postMime = $this->postMime;
        // curl_copy_handle() copies the options the claim arrived with, so
        // the copy is the bridge's transfer too.
        $copy->claimed = $this->claimed;

        return $copy;
    }

    /**
     * curl_reset() returns the handle to its default state.
     */
    public function reset(): void
    {
        $this->options = [];
        $this->appHeaderFunction = null;
        $this->headerTarget = null;
        $this->responseHeaderBuffer = '';
        $this->currentHeaderBlock = '';
        $this->headersTruncated = false;
        $this->capturing = false;
        $this->headersInstalled = false;
        $this->httpRequest = 'GET';
        $this->noBody = false;
        $this->postString = null;
        $this->postMime = null;
        // curl_reset puts the handle back to defaults, which is the one thing
        // that can make a divergent shadow state agree again.
        $this->unsafeReason = null;
        // The claim was one of the options, and the options are gone.
        $this->claimed = false;
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

    /**
     * Record that a bridge has claimed this handle's transfers.
     *
     * The bridge records the exchange itself, with bodies. Recording it here
     * as well gave every call two unlinked records, so a claimed handle is
     * never captured. The claim lasts as long as the options it came with:
     * until curl_reset().
     */
    public function claim(): void
    {
        $this->claimed = true;
    }

    public function isClaimed(): bool
    {
        return $this->claimed;
    }
}
