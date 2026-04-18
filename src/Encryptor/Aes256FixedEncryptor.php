<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\DeterministicEncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;

class Aes256FixedEncryptor extends AbstractEncryptor implements DeterministicEncryptorInterface
{
    public function getTypeClass(): string
    {
        return Aes256FixedType::class;
    }

    protected function generateNonce(string $data): string
    {
        $hash = \hash_hmac('sha256', $data, $this->nonceKey, true);

        return \substr($hash, 0, $this->getInitialVectorLength());
    }
}
