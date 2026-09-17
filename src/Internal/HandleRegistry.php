<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

/**
 * Tracks the shadow state of every live curl handle.
 *
 * Keyed by the CurlHandle object itself. `SplObjectStorage` holds a strong
 * reference, so handles are removed on `curl_close()` and, as a backstop, the
 * registry is capped — a long-running worker that leaks handles must not turn
 * into a memory leak in the instrumentation as well.
 */
final class HandleRegistry
{
    /** @var \SplObjectStorage<object, HandleState> */
    private \SplObjectStorage $handles;

    public function __construct(private readonly int $maxHandles = 1024)
    {
        $this->handles = new \SplObjectStorage();
    }

    public function for(object $handle): HandleState
    {
        if (!$this->handles->contains($handle)) {
            if ($this->handles->count() >= $this->maxHandles) {
                // Something is leaking handles. Drop everything rather than
                // grow without bound; the worst case is losing capture for
                // in-flight transfers, which beats exhausting memory.
                $this->handles = new \SplObjectStorage();
            }

            $this->handles->attach($handle, new HandleState());
        }

        return $this->handles[$handle];
    }

    public function has(object $handle): bool
    {
        return $this->handles->contains($handle);
    }

    public function copy(object $from, object $to): void
    {
        if ($this->handles->contains($from)) {
            $this->handles->attach($to, $this->handles[$from]->copy());
        }
    }

    public function forget(object $handle): void
    {
        if ($this->handles->contains($handle)) {
            $this->handles->detach($handle);
        }
    }

    public function count(): int
    {
        return $this->handles->count();
    }

    public function clear(): void
    {
        $this->handles = new \SplObjectStorage();
    }
}
