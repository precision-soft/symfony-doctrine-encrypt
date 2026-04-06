<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;

/**
 * BREAKING CHANGE: nonce derivation now uses an HKDF-derived nonceKey instead of the raw salt.
 * Existing data encrypted with a previous version will NOT be decryptable.
 * Use the database decrypt/encrypt commands to migrate existing data before upgrading.
 */
class Aes256FixedEncryptor extends AbstractEncryptor
{
    public function getTypeClass(): string
    {
        return Aes256FixedType::class;
    }

    protected function generateNonce(string $data): string
    {
        $ivLength = \openssl_cipher_iv_length(static::ALGORITHM);

        if (false === $ivLength || 0 >= $ivLength) {
            throw new Exception(\sprintf('failed to get IV length for cipher "%s"', static::ALGORITHM));
        }

        $hash = \hash_hmac('sha256', $data, $this->nonceKey, true);

        return \substr($hash, 0, $ivLength);
    }
}
