<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Contract;

use Throwable;

interface ExceptionInterface extends Throwable
{
    /** @return array<string, mixed> */
    public function getContext(): array;

    /** @param array<string, mixed>|null $context */
    public function setContext(?array $context): static;
}
