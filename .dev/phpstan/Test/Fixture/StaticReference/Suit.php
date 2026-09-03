<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\StaticReference;

enum Suit: string
{
    case Hearts = 'hearts';

    public static function first(): self
    {
        return self::cases()[0];
    }
}
