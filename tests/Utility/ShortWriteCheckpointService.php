<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;

/**
 * Writes the first ten bytes only, the way a full disk truncates a write that `file_put_contents()` still reports as a success.
 *
 * @internal
 */
final class ShortWriteCheckpointService extends CheckpointService
{
    protected function writeBytes($handle, string $contents): int|false
    {
        return \fwrite($handle, \substr($contents, 0, 10));
    }
}
