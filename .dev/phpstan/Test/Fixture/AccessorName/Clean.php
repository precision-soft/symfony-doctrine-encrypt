<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\AccessorName;

class Clean implements ReadinessInterface
{
    public function __construct(protected bool $ready = false)
    {
    }

    public function isReady(): bool
    {
        return $this->ready;
    }

    public function getReady(): bool
    {
        return $this->ready;
    }

    public function hasReadiness(): bool
    {
        return $this->ready;
    }

    public function island(): string
    {
        return 'not an accessor';
    }

    protected function isInternal(): bool
    {
        return true;
    }
}
