<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test\Utility;

class FixtureLine
{
    public static function getLine(string $file, string $needle, int $occurrence = 1): int
    {
        $content = \file_get_contents($file);

        if (false === $content) {
            throw new FixtureNeedleNotFoundException(\sprintf('fixture `%s` cannot be read', $file));
        }

        $seen = 0;

        foreach (\explode("\n", $content) as $index => $line) {
            if (false === \str_contains($line, $needle)) {
                continue;
            }

            ++$seen;

            if ($occurrence === $seen) {
                return $index + 1;
            }
        }

        throw new FixtureNeedleNotFoundException(
            \sprintf('occurrence %d of `%s` not found in fixture `%s`', $occurrence, $needle, $file),
        );
    }
}
