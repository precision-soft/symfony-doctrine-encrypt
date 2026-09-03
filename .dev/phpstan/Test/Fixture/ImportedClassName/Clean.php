<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\ImportedClassName;

use ArrayIterator;
use ArrayObject;
use Closure;
use Countable;
use RuntimeException;
use Throwable;

class Clean
{
    public function run(ArrayObject $arrayObject): object
    {
        $iterator = new ArrayIterator([]);

        if (true === $iterator instanceof Countable && \PHP_EOL === \sprintf('%s', \PHP_EOL)) {
            return new ArrayObject(\iterator_to_array($iterator));
        }

        try {
            return Closure::fromCallable('trim');
        } catch (Throwable $throwable) {
            throw new RuntimeException($throwable->getMessage(), \E_ALL);
        }
    }
}
