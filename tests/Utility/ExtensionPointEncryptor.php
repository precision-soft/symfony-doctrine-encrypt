<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;

/**
 * Stands in for a consumer subclass: nothing inside the package reaches the protected extension points, so without this fixture their visibility is asserted nowhere.
 *
 * @internal
 */
final class ExtensionPointEncryptor extends Aes256Encryptor
{
    public function deriveKeyThroughTheExtensionPoint(string $masterKey, string $information): string
    {
        return $this->deriveKey($masterKey, $information);
    }

    public function computeMessageAuthenticationCodeThroughTheExtensionPoint(
        string $formatVersion,
        string $saltVersion,
        string $algorithm,
        string $ciphertext,
        string $nonce,
        string $macKey,
    ): string {
        return $this->computeMessageAuthenticationCode(
            $formatVersion,
            $saltVersion,
            $algorithm,
            $ciphertext,
            $nonce,
            $macKey,
        );
    }

    public function computeLegacyMessageAuthenticationCodeThroughTheExtensionPoint(
        string $algorithm,
        string $ciphertext,
        string $nonce,
        string $macKey,
    ): string {
        return $this->computeLegacyMessageAuthenticationCode($algorithm, $ciphertext, $nonce, $macKey);
    }

    public function looksEncryptedThroughTheExtensionPoint(string $data): bool
    {
        return $this->looksEncrypted($data);
    }

    /** @return array<string, string> */
    public function getNonceKeysBySaltVersionThroughTheExtensionPoint(): array
    {
        return $this->getNonceKeysBySaltVersion();
    }
}
