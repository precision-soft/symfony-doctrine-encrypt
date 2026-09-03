<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\MemberOrder;

abstract class Violation
{
    public function __construct(protected string $name)
    {
    }

    abstract protected function describe(): string;

    public function run(): string
    {
        return $this->describe();
    }

    public static function create(): static
    {
        return new static('name');
    }

    protected const LABEL = 'label';

    protected function helper(): string
    {
        return static::LABEL;
    }

    public function getName(): string
    {
        return $this->name;
    }
}
