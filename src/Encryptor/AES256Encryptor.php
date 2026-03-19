<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;

class AES256Encryptor extends AbstractEncryptor
{
    public function getTypeClass(): string
    {
        return AES256Type::class;
    }

    protected function generateNonce(string $data): string
    {
        $size = \openssl_cipher_iv_length(static::ALGORITHM);

        return \random_bytes($size);
    }
}
