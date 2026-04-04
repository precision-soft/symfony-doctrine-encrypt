<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256FixedType;

/**
 * @internal
 */
final class AES256FixedEncryptorTest extends TestCase
{
    private string $salt;
    private AES256FixedEncryptor $aes256FixedEncryptor;

    protected function setUp(): void
    {
        $this->salt = \str_repeat('b', 32);
        $this->aes256FixedEncryptor = new AES256FixedEncryptor($this->salt);
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $plaintext = 'my-secret-password';

        $encrypted = $this->aes256FixedEncryptor->encrypt($plaintext);
        $decrypted = $this->aes256FixedEncryptor->decrypt($encrypted);

        static::assertSame($plaintext, $decrypted);
    }

    public function testEncryptProducesMarker(): void
    {
        $encrypted = $this->aes256FixedEncryptor->encrypt('value');

        static::assertStringStartsWith(AbstractEncryptor::ENCRYPTION_MARKER, $encrypted);
    }

    public function testEncryptIsDeterministic(): void
    {
        $plaintext = 'same-value';

        $first = $this->aes256FixedEncryptor->encrypt($plaintext);
        $second = $this->aes256FixedEncryptor->encrypt($plaintext);

        static::assertSame($first, $second);
    }

    public function testDecryptPlainTextReturnedAsIs(): void
    {
        $plaintext = 'not-encrypted';

        static::assertSame($plaintext, $this->aes256FixedEncryptor->decrypt($plaintext));
    }

    public function testDecryptInvalidMacThrowsException(): void
    {
        $encrypted = $this->aes256FixedEncryptor->encrypt('value');

        $parts = \explode("\0", $encrypted);
        $parts[2] = \base64_encode(\str_repeat('x', 32));
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $this->aes256FixedEncryptor->decrypt($tampered);
    }

    public function testSaltTooShortThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid encryption salt');

        new AES256FixedEncryptor('short');
    }

    public function testEncryptEmptyStringIsDeterministic(): void
    {
        $first = $this->aes256FixedEncryptor->encrypt('');
        $second = $this->aes256FixedEncryptor->encrypt('');

        static::assertSame($first, $second);
    }

    public function testGetTypeClassReturnsAES256FixedType(): void
    {
        static::assertSame(AES256FixedType::class, $this->aes256FixedEncryptor->getTypeClass());
    }

    public function testGetTypeNameReturnsFullName(): void
    {
        static::assertSame(AES256FixedType::getFullName(), $this->aes256FixedEncryptor->getTypeName());
    }
}
