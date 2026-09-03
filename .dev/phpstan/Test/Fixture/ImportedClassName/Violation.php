<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\ImportedClassName;

use ArrayObject;

class Violation
{
    #[\ReturnTypeWillChange]
    public function run(\ArrayObject $arrayObject): object
    {
        $iterator = new \ArrayIterator([]);

        if (true === $iterator instanceof \Countable) {
            return new ArrayObject(\iterator_to_array($iterator));
        }

        try {
            return \Closure::fromCallable('trim');
        } catch (\Throwable $throwable) {
            throw new \RuntimeException($throwable->getMessage());
        }
    }
}
