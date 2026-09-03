<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\StaticReference;

class Violation
{
    public const NAME = 'name';
    protected static int $counter = 0;

    public static function create(): static
    {
        return new self();
    }

    public function run(): string
    {
        self::$counter++;

        return self::NAME . self::describe();
    }

    protected static function describe(): string
    {
        return self::class;
    }
}
