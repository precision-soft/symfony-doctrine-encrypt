<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;

/**
 * @internal
 */
final class Aes256FixedEncryptorTest extends TestCase
{
    private string $salt;
    private Aes256FixedEncryptor $aes256FixedEncryptor;

    protected function setUp(): void
    {
        $this->salt = \str_repeat('b', 32);
        $this->aes256FixedEncryptor = new Aes256FixedEncryptor($this->salt);
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
        $this->expectExceptionMessage('invalid message authentication code');

        $this->aes256FixedEncryptor->decrypt($tampered);
    }

    public function testSaltTooShortThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid encryption salt');

        new Aes256FixedEncryptor('short');
    }

    public function testEncryptEmptyStringIsDeterministic(): void
    {
        $first = $this->aes256FixedEncryptor->encrypt('');
        $second = $this->aes256FixedEncryptor->encrypt('');

        static::assertSame($first, $second);
    }

    public function testGetTypeClassReturnsAes256FixedType(): void
    {
        static::assertSame(Aes256FixedType::class, $this->aes256FixedEncryptor->getTypeClass());
    }

    public function testGetTypeNameReturnsFullName(): void
    {
        static::assertSame(Aes256FixedType::getFullName(), $this->aes256FixedEncryptor->getTypeName());
    }
}
