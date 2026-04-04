<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256FixedType;

/**
 * @internal
 */
final class AES256FixedTypeTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private AES256FixedType $aes256FixedType;
    private AES256FixedEncryptor $aes256FixedEncryptor;

    protected function setUp(): void
    {
        if (false === Type::hasType(AES256FixedType::getFullName())) {
            Type::addType(AES256FixedType::getFullName(), AES256FixedType::class);
        }

        /** @var AES256FixedType $aes256FixedType */
        $aes256FixedType = Type::getType(AES256FixedType::getFullName());
        $this->aes256FixedType = $aes256FixedType;
        $this->aes256FixedEncryptor = new AES256FixedEncryptor(\str_repeat('c', 32));
        $this->aes256FixedType->setEncryptor($this->aes256FixedEncryptor);
    }

    public function testConvertToDatabaseValueEncryptsValue(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $result = $this->aes256FixedType->convertToDatabaseValue('plaintext', $platform);

        static::assertNotSame('plaintext', $result);
        static::assertStringStartsWith('<ENC>', (string)$result);
    }

    public function testConvertToPHPValueDecryptsValue(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $encrypted = $this->aes256FixedEncryptor->encrypt('plaintext');
        $result = $this->aes256FixedType->convertToPHPValue($encrypted, $platform);

        static::assertSame('plaintext', $result);
    }

    public function testConvertToDatabaseValueNullReturnsNull(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        static::assertSame(null, $this->aes256FixedType->convertToDatabaseValue(null, $platform));
    }

    public function testConvertToPHPValueNullReturnsNull(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        static::assertSame(null, $this->aes256FixedType->convertToPHPValue(null, $platform));
    }

    public function testConvertWithoutEncryptorThrowsException(): void
    {
        if (false === Type::hasType('encryptedAES256fixed_test')) {
            Type::addType('encryptedAES256fixed_test', AES256FixedType::class);
        }

        /** @var AES256FixedType $bareType */
        $bareType = Type::getType('encryptedAES256fixed_test');

        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the encryptor was not set');

        $bareType->convertToDatabaseValue('value', $platform);
    }

    public function testRoundTripThroughType(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $encrypted = $this->aes256FixedType->convertToDatabaseValue('original', $platform);
        $decrypted = $this->aes256FixedType->convertToPHPValue($encrypted, $platform);

        static::assertSame('original', $decrypted);
    }

    public function testEncryptIsDeterministic(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $first = $this->aes256FixedType->convertToDatabaseValue('same-value', $platform);
        $second = $this->aes256FixedType->convertToDatabaseValue('same-value', $platform);

        static::assertSame($first, $second);
    }
}
