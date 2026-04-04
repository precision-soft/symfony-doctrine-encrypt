<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

class Aes256Encryptor extends AbstractEncryptor
{
    public function getTypeClass(): string
    {
        return Aes256Type::class;
    }

    protected function generateNonce(string $data): string
    {
        $ivLength = \openssl_cipher_iv_length(static::ALGORITHM);

        if (false === $ivLength || 0 >= $ivLength) {
            throw new Exception(\sprintf('failed to get IV length for cipher "%s"', static::ALGORITHM));
        }

        return \random_bytes($ivLength);
    }
}
