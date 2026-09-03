<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\AccessorName;

class Violation
{
    public function __construct(protected bool $ready = false)
    {
    }

    public function isReady(): bool
    {
        return $this->ready;
    }

    public function is2faEnabled(): bool
    {
        return false;
    }
}
