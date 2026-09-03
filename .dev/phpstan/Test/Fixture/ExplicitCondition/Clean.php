<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\ExplicitCondition;

use ArrayObject;

class Clean
{
    /** @param list<string> $items */
    public function run(bool $flag, ?string $value, array $items, object $object): string
    {
        if (true === $flag) {
            return 'a';
        }

        if (true === isset($items[0]) || null === $value) {
            return 'b';
        }

        while (0 < \count($items)) {
            \array_pop($items);
        }

        if (true === $object instanceof ArrayObject) {
            return 'c';
        }

        for ($index = 0; $index < 2; ++$index) {
            $flag = false;
        }

        if (false) {
            return 'd';
        }

        $result = match (true) {
            null === $value => 'e',
            default => $value ?? 'f',
        };

        return true === $flag ? $result : 'g';
    }
}
