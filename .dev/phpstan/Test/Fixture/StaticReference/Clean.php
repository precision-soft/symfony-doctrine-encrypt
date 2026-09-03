<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\StaticReference;

class Clean
{
    public const NAME = 'name';
    public const ALIAS = self::NAME;
    protected static int $counter = 0;

    public static function create(): static
    {
        return new static();
    }

    #[Marker(self::NAME)]
    public function run(string $name = self::NAME): string
    {
        static::$counter++;

        $closure = static fn(string $value = self::NAME): string => $value;

        return static::NAME . static::describe() . $closure() . self::class;
    }

    protected static function describe(): string
    {
        return static::class;
    }
}
