<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;

/**
 * Used internally during the encrypt/decrypt migration commands (AbstractDatabaseCommand::resetEncryptorsToFake)
 * to act as a pass-through that returns data unmodified, allowing reading already-decrypted values during
 * the re-encryption workflow.
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
