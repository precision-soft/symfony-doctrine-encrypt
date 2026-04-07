<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Contract;

interface EncryptorInterface
{
    /** @return ?string null for encryptors without a dedicated DBAL type (e.g. FakeEncryptor) */
    public function getTypeClass(): ?string;

    /** @return ?string null for encryptors without a dedicated DBAL type (e.g. FakeEncryptor) */
    public function getTypeName(): ?string;

    public function encrypt(string $data): string;

    public function decrypt(string $data): string;
}
