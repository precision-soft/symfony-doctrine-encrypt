<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Support;

class PathGuard
{
    /** @param list<string> $libraryPathList */
    public function __construct(protected readonly array $libraryPathList) {}

    public function containsFile(string $file): bool
    {
        foreach ($this->libraryPathList as $libraryPath) {
            if (true === \str_starts_with($file, \rtrim($libraryPath, '/') . '/')) {
                return true;
            }
        }

        return false;
    }
}
