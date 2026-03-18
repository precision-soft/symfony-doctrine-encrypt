<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;

/**
 * @internal
 */
final class AES256EncryptorTest extends TestCase
{
    private string $salt;
    private AES256Encryptor $encryptor;

    protected function setUp(): void
    {
        $this->salt = \str_repeat('a', 32);
        $this->encryptor = new AES256Encryptor($this->salt);
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $plaintext = 'my-secret-password';

        $encrypted = $this->encryptor->encrypt($plaintext);
        $decrypted = $this->encryptor->decrypt($encrypted);

        static::assertSame($plaintext, $decrypted);
    }

    public function testEncryptProducesMarker(): void
    {
        $encrypted = $this->encryptor->encrypt('value');

        static::assertStringStartsWith(AbstractEncryptor::ENCRYPTION_MARKER, $encrypted);
    }

    public function testEncryptIsNonDeterministic(): void
    {
        $plaintext = 'same-value';

        $first = $this->encryptor->encrypt($plaintext);
        $second = $this->encryptor->encrypt($plaintext);

        static::assertNotSame($first, $second);
    }

    public function testDecryptPlainTextReturnedAsIs(): void
    {
        $plaintext = 'not-encrypted';

        static::assertSame($plaintext, $this->encryptor->decrypt($plaintext));
    }

    public function testDecryptInvalidMacThrowsException(): void
    {
        $encrypted = $this->encryptor->encrypt('value');

        /* tamper with the mac portion */
        $parts = \explode("\0", $encrypted);
        $parts[2] = \base64_encode(\str_repeat('x', 32));
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $this->encryptor->decrypt($tampered);
    }

    public function testSaltTooShortThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid encryption salt');

        new AES256Encryptor('short');
    }

    public function testGetTypeClassReturnsAES256Type(): void
    {
        static::assertSame(AES256Type::class, $this->encryptor->getTypeClass());
    }

    public function testGetTypeNameReturnsFullName(): void
    {
        static::assertSame(AES256Type::getFullName(), $this->encryptor->getTypeName());
    }
}
