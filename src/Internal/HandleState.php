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

    private string $responseHeaderBuffer = '';

    private float $startedAt = 0.0;

    private bool $capturing = false;

    private bool $headersInstalled = false;

    /** @var callable|null */
    private $appHeaderFunction = null;

    public function set(int $option, mixed $value): void
    {
        $this->options[$option] = $value;

        // Remember the application's own header callback so ours can chain
        // onto it rather than silently replacing it.
        if ($option === CURLOPT_HEADERFUNCTION && is_callable($value)) {
            $this->appHeaderFunction = $value;
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
            return strtoupper($this->options[CURLOPT_CUSTOMREQUEST]);
        }

        if (($this->options[CURLOPT_NOBODY] ?? false) === true) {
            return 'HEAD';
        }

        if (($this->options[CURLOPT_POST] ?? false) === true || isset($this->options[CURLOPT_POSTFIELDS])) {
            return 'POST';
        }

        if (isset($this->options[CURLOPT_PUT]) && $this->options[CURLOPT_PUT] === true) {
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
        return ($this->options[CURLOPT_VERBOSE] ?? false) !== true;
    }

    public function returnsTransfer(): bool
    {
        return ($this->options[CURLOPT_RETURNTRANSFER] ?? false) === true;
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

    public function appendResponseHeader(string $line): void
    {
        // Bounded, so a misbehaving server cannot grow this without limit.
        if (strlen($this->responseHeaderBuffer) < 65536) {
            $this->responseHeaderBuffer .= $line;
        }
    }

    public function responseHeaders(): string
    {
        return $this->responseHeaderBuffer;
    }

    public function beginTransfer(bool $capturing): void
    {
        $this->capturing = $capturing;
        $this->startedAt = microtime(true);
        $this->responseHeaderBuffer = '';
    }

    public function isCapturing(): bool
    {
        return $this->capturing;
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
        $this->capturing = false;
        $this->headersInstalled = false;
    }
}
