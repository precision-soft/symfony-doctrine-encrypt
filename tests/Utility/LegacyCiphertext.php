<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PHPUnit\Framework\Assert;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;

/**
 * @internal
 */
final class LegacyCiphertext
{
    private const ALGORITHM = 'AES-256-CTR';

    /* the four part envelope predates format and salt versions, so it is the shape rotation has to be able to read and rewrite */
    public static function produce(string $salt, string $plaintext): string
    {
        $encryptionKey = \hash_hkdf('sha256', $salt, 32, 'encryption');
        $macKey = \hash_hkdf('sha256', $salt, 32, 'authentication');
        $nonce = \random_bytes(16);

        $ciphertext = \openssl_encrypt($plaintext, static::ALGORITHM, $encryptionKey, \OPENSSL_RAW_DATA, $nonce);

        Assert::assertIsString($ciphertext, 'Expected the legacy fixture to encrypt.');

        $messageAuthenticationCode = \hash_hmac('sha256', static::ALGORITHM . $ciphertext . $nonce, $macKey, true);

        return \implode(
            AbstractEncryptor::GLUE,
            [
                AbstractEncryptor::ENCRYPTION_MARKER,
                \base64_encode($ciphertext),
                \base64_encode($messageAuthenticationCode),
                \base64_encode($nonce),
            ],
        );
    }
}
