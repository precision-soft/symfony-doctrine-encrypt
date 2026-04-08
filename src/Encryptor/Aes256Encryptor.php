<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

class Aes256Encryptor extends AbstractEncryptor
{
    public function getTypeClass(): string
    {
        return Aes256Type::class;
    }

    protected function generateNonce(string $data): string
    {
        return \random_bytes($this->getInitialVectorLength());
    }
}
