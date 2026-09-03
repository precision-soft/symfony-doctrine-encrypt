<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\Negation;

class Clean
{
    public function run(bool $flag, ?string $value): bool
    {
        if (false === $flag || null !== $value) {
            return false;
        }

        return false === \is_string($value);
    }
}
