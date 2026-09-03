<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\StaticReference;

final class Sealed
{
    public function run(): string
    {
        return self::class . self::describe();
    }

    private static function describe(): string
    {
        return 'sealed';
    }
}
