<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

/**
 * Tracks the shadow state of every live curl handle.
 *
 * Keyed by the CurlHandle object in a WeakMap, so tracking a handle does not
 * keep it alive. SplObjectStorage held a strong reference, which had two
 * consequences worth spelling out:
 *
 *  - An application that dropped its last reference to a handle, rather than
 *    calling curl_close(), had that handle, its callbacks and its shadowed
 *    POST body retained until the process ended. Instrumentation changed the
 *    lifetime of the thing it was observing.
 *  - curl_copy_handle() attached copies without consulting the capacity limit,
 *    so repeatedly copying and dropping handles grew without bound regardless
 *    of maxHandles.
 *
 * A WeakMap fixes both: entries disappear when the application is finished
 * with a handle, and there is nothing to leak. The cap remains as a backstop.
 */
final class HandleRegistry
{
    /** @var \WeakMap<object, HandleState> */
    private \WeakMap $handles;

    public function __construct(private readonly int $maxHandles = 1024)
    {
        /** @var \WeakMap<object, HandleState> $map */
        $map = new \WeakMap();
        $this->handles = $map;
    }

    public function for(object $handle): HandleState
    {
        if (!$this->handles->offsetExists($handle)) {
            $this->enforceCapacity();
            $this->handles[$handle] = new HandleState();
        }

        return $this->handles[$handle];
    }

    public function has(object $handle): bool
    {
        return $this->handles->offsetExists($handle);
    }

    public function copy(object $from, object $to): void
    {
        if (!$this->handles->offsetExists($from)) {
            return;
        }

        // Read the source state before the capacity check: enforcing capacity
        // can clear the map, and the source would no longer be in it.
        $copied = $this->handles[$from]->copy();

        // Copies go through the same capacity check as any other insertion.
        $this->enforceCapacity();

        $this->handles[$to] = $copied;
    }

    public function forget(object $handle): void
    {
        if ($this->handles->offsetExists($handle)) {
            $this->handles->offsetUnset($handle);
        }
    }

    public function count(): int
    {
        return count($this->handles);
    }

    public function clear(): void
    {
        /** @var \WeakMap<object, HandleState> $map */
        $map = new \WeakMap();
        $this->handles = $map;
    }

    /**
     * Something is holding far more handles than any application needs.
     * Dropping the shadow state costs capture for in-flight transfers, which
     * beats unbounded growth inside instrumentation.
     */
    private function enforceCapacity(): void
    {
        if (count($this->handles) >= $this->maxHandles) {
            $this->clear();
        }
    }
}
