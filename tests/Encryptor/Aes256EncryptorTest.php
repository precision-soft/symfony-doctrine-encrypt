<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

/**
 * @internal
 */
final class Aes256EncryptorTest extends TestCase
{
    private string $salt;
    private Aes256Encryptor $aes256Encryptor;

    protected function setUp(): void
    {
        $this->salt = \str_repeat('a', 32);
        $this->aes256Encryptor = new Aes256Encryptor($this->salt);
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $plaintext = 'my-secret-password';

        $encrypted = $this->aes256Encryptor->encrypt($plaintext);
        $decrypted = $this->aes256Encryptor->decrypt($encrypted);

        static::assertSame($plaintext, $decrypted);
    }

    public function testEncryptProducesMarker(): void
    {
        $encrypted = $this->aes256Encryptor->encrypt('value');

        static::assertStringStartsWith(AbstractEncryptor::ENCRYPTION_MARKER, $encrypted);
    }

    public function testEncryptIsNonDeterministic(): void
    {
        $plaintext = 'same-value';

        $first = $this->aes256Encryptor->encrypt($plaintext);
        $second = $this->aes256Encryptor->encrypt($plaintext);

        static::assertNotSame($first, $second);
    }

    public function testDecryptPlainTextReturnedAsIs(): void
    {
        $plaintext = 'not-encrypted';

        static::assertSame($plaintext, $this->aes256Encryptor->decrypt($plaintext));
    }

    public function testDecryptInvalidMacThrowsException(): void
    {
        $encrypted = $this->aes256Encryptor->encrypt('value');

        $parts = \explode("\0", $encrypted);
        $parts[2] = \base64_encode(\str_repeat('x', 32));
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $this->aes256Encryptor->decrypt($tampered);
    }

    public function testSaltTooShortThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid encryption salt');

        new Aes256Encryptor('short');
    }

    public function testGetTypeClassReturnsAes256Type(): void
    {
        static::assertSame(Aes256Type::class, $this->aes256Encryptor->getTypeClass());
    }

    public function testGetTypeNameReturnsFullName(): void
    {
        static::assertSame(Aes256Type::getFullName(), $this->aes256Encryptor->getTypeName());
    }

    public function testEncryptAlreadyEncryptedDataIsIdempotent(): void
    {
        $plaintext = 'my-secret-password';

        $encrypted = $this->aes256Encryptor->encrypt($plaintext);
        $doubleEncrypted = $this->aes256Encryptor->encrypt($encrypted);

        static::assertSame($encrypted, $doubleEncrypted);
    }

    public function testEncryptMarkerLookalikeWithInvalidBase64IsEncryptedNormally(): void
    {
        $lookalike = AbstractEncryptor::ENCRYPTION_MARKER . "\0!!!invalid!!!\0!!!invalid!!!\0!!!invalid!!!";

        $encrypted = $this->aes256Encryptor->encrypt($lookalike);

        static::assertNotSame($lookalike, $encrypted);
        static::assertSame($lookalike, $this->aes256Encryptor->decrypt($encrypted));
    }

    public function testEncryptMarkerLookalikeWithTooFewPartsIsEncryptedNormally(): void
    {
        $lookalike = AbstractEncryptor::ENCRYPTION_MARKER . "\0" . \base64_encode('only-two-parts');

        $encrypted = $this->aes256Encryptor->encrypt($lookalike);

        static::assertNotSame($lookalike, $encrypted);
        static::assertSame($lookalike, $this->aes256Encryptor->decrypt($encrypted));
    }
}
