<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\ExplicitCondition;

use ArrayObject;

class Violation
{
    /** @param list<string> $items */
    public function run(bool $flag, ?string $value, array $items, object $object): string
    {
        if ($flag) {
            return 'a';
        }

        if (isset($items[0])) {
            return 'b';
        }

        while (\count($items)) {
            \array_pop($items);
        }

        if ($object instanceof ArrayObject) {
            return 'c';
        }

        if (true === $flag && $value) {
            return 'd';
        }

        $result = $value ?: 'e';

        return $flag ? $result : 'f';
    }
}
