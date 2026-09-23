<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

/**
 * A reference to an application callback that does not keep it alive.
 *
 * The shadow state lives in a WeakMap keyed by the curl handle. On PHP 8.2 a
 * WeakMap entry whose value refers back to its own key is never collected:
 * the value keeps the key alive, and the key is what would have removed the
 * value. A header callback is almost always a closure or a method bound to
 * the object that owns the handle, so holding it strongly here kept the
 * handle, its owner and everything the owner referenced alive until the
 * process ended — and once the registry filled up, capture stopped for every
 * handle in the process.
 *
 * Holding the callback weakly is safe because curl holds it strongly for as
 * long as it matters: the handle keeps the application's callback until our
 * wrapper replaces it, and at that moment the wrapper takes its own strong
 * reference, on the handle rather than in the map.
 */
final class CallbackRef
{
    /**
     * @param \WeakReference<object>|null $object
     */
    private function __construct(
        private readonly ?\WeakReference $object,
        private readonly ?string $name,
        private readonly bool $isMethod,
    ) {
    }

    public static function of(mixed $callback): self
    {
        if (is_string($callback)) {
            return new self(null, $callback, false);
        }

        if (is_object($callback)) {
            return new self(\WeakReference::create($callback), null, false);
        }

        if (is_array($callback) && count($callback) === 2 && isset($callback[0], $callback[1]) && is_string($callback[1])) {
            if (is_object($callback[0])) {
                return new self(\WeakReference::create($callback[0]), $callback[1], true);
            }

            if (is_string($callback[0])) {
                return new self(null, $callback[0] . '::' . $callback[1], false);
            }
        }

        // Not a shape any callable takes. curl would fail on it at transfer
        // time; all we need to know is that we cannot call it either.
        return new self(null, null, false);
    }

    /**
     * The callback as the application gave it, or null if it cannot be
     * rebuilt. Returned without checking callability: that depends on the
     * scope asking.
     */
    public function resolve(): mixed
    {
        if ($this->object === null) {
            return $this->name;
        }

        $target = $this->object->get();

        if ($target === null) {
            return null;
        }

        return $this->isMethod ? [$target, $this->name] : $target;
    }
}
