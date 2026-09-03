<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\MemberOrder;

use Countable;

abstract class Clean implements Countable
{
    use Named;

    public const LABEL = 'label';
    protected const INNER_LABEL = 'inner';
    private const SECRET_LABEL = 'secret';
    public static int $publicCounter = 0;
    protected static int $counter = 0;
    public int $publicValue = 0;
    protected int $value = 0;
    private int $secret = 0;

    abstract protected function describe(): string;

    public function __construct(protected string $name)
    {
    }

    public function __toString(): string
    {
        return $this->name . static::SECRET_LABEL . $this->secret;
    }

    public static function getMockDto(): string
    {
        return 'a public static method like any other';
    }

    public static function create(): static
    {
        return new static('name');
    }

    protected static function build(): static
    {
        return static::create();
    }

    private static function seed(): int
    {
        return 1;
    }

    public function count(): int
    {
        return static::seed();
    }

    protected function setUp(): void
    {
        $this->value = 1;
    }

    protected function helper(): string
    {
        return static::INNER_LABEL;
    }

    private function secret(): int
    {
        return $this->secret;
    }
}
