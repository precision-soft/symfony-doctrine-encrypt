<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Type\AES256FixedType;

class AES256FixedEncryptor extends AbstractEncryptor
{
    public function getTypeClass(): string
    {
        return AES256FixedType::class;
    }

    protected function generateNonce(string $data): string
    {
        $size = \openssl_cipher_iv_length(static::ALGORITHM);
        $hash = \hash_hmac('sha256', $data, $this->salt, true);

        return \substr($hash, 0, $size);
    }
}
