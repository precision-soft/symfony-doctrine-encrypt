<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;

/**
 * @info pass-through encryptor used only during the encrypt/decrypt migration commands so re-reads do not re-encrypt/decrypt in-flight data
 * @internal
 */
class FakeEncryptor implements EncryptorInterface
{
    public function getTypeClass(): ?string
    {
        return null;
    }

    public function getTypeName(): ?string
    {
        return null;
    }

    public function encrypt(string $data): string
    {
        return $data;
    }

    public function decrypt(string $data): string
    {
        return $data;
    }
}
