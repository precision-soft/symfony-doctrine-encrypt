<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\YodaComparison;

class Violation
{
    public const LIMIT = 1;

    /** @param list<string> $items */
    public function run(?string $value, array $items, int $count): bool
    {
        if ($value === null) {
            return false;
        }

        if ($items == []) {
            return false;
        }

        if ($count !== -1) {
            return false;
        }

        return $count != static::LIMIT;
    }
}
