<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Auto\Internal;

/**
 * What curl_multi_exec() has said about one multi handle.
 *
 * curl reports how each transfer ended only through curl_multi_info_read(),
 * and reading that here would take the message from the application. What
 * curl_multi_exec() reports through its still_running argument is free to
 * observe, and it is enough to know whether a transfer had finished when it
 * was removed: every transfer added before an exec that reported nothing
 * running has finished.
 *
 * Holds no handles, so a HandleState can refer to it without keeping either
 * handle alive.
 */
final class MultiProgress
{
    private int $execs = 0;

    /**
     * The exec count at the last exec that reported nothing running.
     */
    private int $idleAt = -1;

    public function executed(mixed $running): void
    {
        ++$this->execs;

        if ($running === 0) {
            $this->idleAt = $this->execs;
        }
    }

    public function execs(): int
    {
        return $this->execs;
    }

    /**
     * @param int $addedAt the exec count when the transfer was added
     *
     * @return 'unstarted'|'running'|'finished'
     */
    public function phaseOf(int $addedAt): string
    {
        if ($this->execs <= $addedAt) {
            return 'unstarted';
        }

        return $this->idleAt > $addedAt ? 'finished' : 'running';
    }
}
