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
        $dataSize = \strlen($data);

        if (0 === $dataSize) {
            $dataSize = 10;
            $data = \str_repeat('0', $dataSize);
        }

        $size = \openssl_cipher_iv_length(static::ALGORITHM);
        $nonce = '';

        for ($position = 1; $position <= $size; ++$position) {
            $nonce .= $data[($position - 1) % $dataSize];
        }

        return $nonce;
    }
}
