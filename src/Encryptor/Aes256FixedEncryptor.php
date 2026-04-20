<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\DeterministicEncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;

class Aes256FixedEncryptor extends AbstractEncryptor implements DeterministicEncryptorInterface
{
    public function getTypeClass(): string
    {
        return Aes256FixedType::class;
    }

    protected function generateNonce(string $data): string
    {
        return $this->generateNonceForSaltVersion($data, $this->currentSaltVersion);
    }

    /** @info deterministic nonces MUST be produced under the correct epoch's nonce key so that WHERE lookups across a rotation window can enumerate every candidate ciphertext — see SDE-153 */
    protected function generateNonceForSaltVersion(string $data, string $saltVersion): string
    {
        $nonceKeys = $this->getNonceKeysBySaltVersion();

        if (false === \array_key_exists($saltVersion, $nonceKeys)) {
            throw new Exception(\sprintf('unknown salt version `%s`', $saltVersion));
        }

        $hash = \hash_hmac('sha256', $data, $nonceKeys[$saltVersion], true);

        return \substr($hash, 0, $this->getInitialVectorLength());
    }
}
