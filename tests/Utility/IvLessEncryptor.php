<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

/**
 * Claims a cipher with no initialisation vector, the only way to reach `getInitialVectorLength()`'s guard: `openssl_cipher_iv_length('aes-256-ecb')` returns 0, not false.
 *
 * @internal
 */
final class IvLessEncryptor extends AbstractEncryptor
{
    protected const ALGORITHM = 'aes-256-ecb';

    public function getTypeClass(): string
    {
        return Aes256Type::class;
    }

    public function getInitialVectorLengthThroughTheExtensionPoint(): int
    {
        return $this->getInitialVectorLength();
    }

    protected function generateNonce(string $data): string
    {
        return \random_bytes($this->getInitialVectorLength());
    }
}
