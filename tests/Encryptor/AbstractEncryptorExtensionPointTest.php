<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\ExtensionPointEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\ExtensionPointType;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IvLessEncryptor;

/**
 * An encryptor's `protected` surface is public API for anyone subclassing it, and the package never reaches it from a subclass — so it is asserted here through consumer stand-ins.
 *
 * @internal
 */
final class AbstractEncryptorExtensionPointTest extends TestCase
{
    private const SALT = 'abcdefghijklmnopqrstuvwxyz123456';

    public function testASubclassCanDeriveKeysThroughTheExtensionPoint(): void
    {
        $extensionPointEncryptor = new ExtensionPointEncryptor(self::SALT);

        $encryptionKey = $extensionPointEncryptor->deriveKeyThroughTheExtensionPoint(self::SALT, 'encryption');

        static::assertSame(32, \strlen($encryptionKey));
        static::assertSame(
            $encryptionKey,
            $extensionPointEncryptor->deriveKeyThroughTheExtensionPoint(self::SALT, 'encryption'),
        );
        static::assertNotSame(
            $encryptionKey,
            $extensionPointEncryptor->deriveKeyThroughTheExtensionPoint(self::SALT, 'authentication'),
        );
    }

    public function testASubclassCanComputeBothMessageAuthenticationCodesThroughTheExtensionPoint(): void
    {
        $extensionPointEncryptor = new ExtensionPointEncryptor(self::SALT);

        $current = $extensionPointEncryptor->computeMessageAuthenticationCodeThroughTheExtensionPoint(
            AbstractEncryptor::FORMAT_VERSION_V1,
            AbstractEncryptor::DEFAULT_SALT_VERSION,
            'AES-256-CTR',
            'ciphertext',
            'nonce',
            'mac-key',
        );
        $legacy = $extensionPointEncryptor->computeLegacyMessageAuthenticationCodeThroughTheExtensionPoint(
            'AES-256-CTR',
            'ciphertext',
            'nonce',
            'mac-key',
        );

        static::assertSame(32, \strlen($current));
        static::assertSame(32, \strlen($legacy));
        static::assertNotSame($current, $legacy);
    }

    public function testASubclassCanReuseTheAlreadyEncryptedGuardThroughTheExtensionPoint(): void
    {
        $extensionPointEncryptor = new ExtensionPointEncryptor(self::SALT);

        static::assertTrue(
            $extensionPointEncryptor->looksEncryptedThroughTheExtensionPoint(
                $extensionPointEncryptor->encrypt('value'),
            ),
        );
        static::assertFalse($extensionPointEncryptor->looksEncryptedThroughTheExtensionPoint('value'));
    }

    public function testASubclassCanReadTheNonceKeysThroughTheExtensionPoint(): void
    {
        $extensionPointEncryptor = new ExtensionPointEncryptor(self::SALT);

        static::assertSame(
            [AbstractEncryptor::DEFAULT_SALT_VERSION],
            \array_keys($extensionPointEncryptor->getNonceKeysBySaltVersionThroughTheExtensionPoint()),
        );
    }

    public function testASubclassCanReuseTheEncryptorPresenceCheckThroughTheExtensionPoint(): void
    {
        $extensionPointType = new ExtensionPointType();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the encryptor was not set');

        $extensionPointType->validateThroughTheExtensionPoint();
    }

    public function testACipherWithoutAnInitialisationVectorIsRejected(): void
    {
        $ivLessEncryptor = new IvLessEncryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('failed to get IV length for cipher "aes-256-ecb"');

        $ivLessEncryptor->getInitialVectorLengthThroughTheExtensionPoint();
    }

    public function testAnEmptySaltsMapIsRefusedWithItsOwnMessage(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('at least one salt is required');

        new Aes256Encryptor([]);
    }

    /* must stay on a random-nonce encryptor: a deterministic one raises the identical message one frame deeper, so the same test against `Aes256FixedEncryptor` passes with the guard removed */
    public function testEncryptingUnderAnUnknownSaltVersionIsRefusedBeforeAnyCryptography(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('unknown salt version `no-such-version`');

        $aes256Encryptor->encryptWithSaltVersion('value', 'no-such-version');
    }

    /* pinned as a vector rather than re-derived, so the test cannot drift with the code it protects */
    public function testTheDeterministicNonceDerivationIsPinned(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(\str_repeat('a', 32));

        $encryptedParts = \explode(
            AbstractEncryptor::GLUE,
            $aes256FixedEncryptor->encrypt('deterministic-nonce-contract'),
        );

        static::assertCount(6, $encryptedParts);
        static::assertSame('rcosW+2htHGxyL+zMfLQJw==', $encryptedParts[5]);
    }
}
