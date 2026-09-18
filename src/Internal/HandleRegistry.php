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
        if ($this->handles->offsetExists($handle)) {
            return $this->handles[$handle];
        }

        if (count($this->handles) >= $this->maxHandles) {
            return $this->untracked();
        }

        $this->handles[$handle] = new HandleState();

        return $this->handles[$handle];
    }

    /**
     * A throwaway state for a handle we have declined to track.
     *
     * At capacity the registry used to clear itself, which discarded the state
     * of handles that were still live and still instrumented. Their recorded
     * CURLOPT_HEADERFUNCTION went with it, so the next capture on one of those
     * handles installed a fresh wrapper with nothing to chain onto and the
     * application's own header callback stopped being called — instrumentation
     * silently removing application behaviour.
     *
     * Declining the new handle instead costs capture for that handle only, and
     * costs nothing that was already working. The state is marked unsafe so
     * the exec hook declines capture and never installs a wrapper on it, and
     * it is not stored, so nothing accumulates. Entries for handles the
     * application has finished with drop out of the WeakMap on their own,
     * which is how capacity comes back.
     */
    private function untracked(): HandleState
    {
        $state = new HandleState();
        $state->markUnsafe('handle registry is at capacity; this handle is not tracked');

        return $state;
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

        // Copies go through the same capacity check as any other insertion,
        // and are declined the same way rather than evicting anyone.
        if (!$this->handles->offsetExists($to) && count($this->handles) >= $this->maxHandles) {
            return;
        }

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

}
