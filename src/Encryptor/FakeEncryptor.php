<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;

/**
 * Registered unconditionally, yet reachable by no entity field, because `getTypeName()` is null; the migration commands swap it in so re-reads do not re-encrypt in-flight data.
 *
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
