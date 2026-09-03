<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\YodaComparison;

class Clean
{
    public const LIMIT = 1;

    /** @param list<string> $items */
    public function run(?string $value, array $items, int $count, string $other): bool
    {
        if (null === $value || [] === $items || -1 !== $count || 1 < $count || $count > 2) {
            return false;
        }

        if ($value === $other || 'a' === 'b' || static::LIMIT === $count) {
            return false;
        }

        return static::LIMIT != $count || "$value" === $other;
    }
}
