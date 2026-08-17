<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Exception\Trait;

trait ExceptionTrait
{
    /** @var array<string, mixed>|null */
    protected ?array $context = null;

    /** @return array<string, mixed> */
    public function getContext(): array
    {
        return $this->context ?? [];
    }

    /** @param array<string, mixed>|null $context */
    public function setContext(?array $context): static
    {
        $this->context = $context;

        return $this;
    }
}
