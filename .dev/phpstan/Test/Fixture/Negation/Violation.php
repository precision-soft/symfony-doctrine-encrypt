<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\Negation;

class Violation
{
    public function run(bool $flag, ?string $value): bool
    {
        if (!$flag) {
            return false;
        }

        return !\is_string($value);
    }
}
