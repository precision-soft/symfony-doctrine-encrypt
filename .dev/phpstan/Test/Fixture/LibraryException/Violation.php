<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\LibraryException;

use InvalidArgumentException;

class Violation
{
    public function run(int $value): never
    {
        if (0 === $value) {
            throw new InvalidArgumentException('value must not be zero');
        }

        throw new \RuntimeException('unexpected value');
    }
}
