<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Mockery;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256FixedType;

/**
 * @internal
 */
final class AES256FixedTypeTest extends TestCase
{
    private AES256FixedType $type;
    private AES256FixedEncryptor $encryptor;

    protected function setUp(): void
    {
        if (false === Type::hasType(AES256FixedType::getFullName())) {
            Type::addType(AES256FixedType::getFullName(), AES256FixedType::class);
        }

        /** @var AES256FixedType $type */
        $type = Type::getType(AES256FixedType::getFullName());
        $this->type = $type;
        $this->encryptor = new AES256FixedEncryptor(\str_repeat('c', 32));
        $this->type->setEncryptor($this->encryptor);
    }

    public function testConvertToDatabaseValueEncryptsValue(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $result = $this->type->convertToDatabaseValue('plaintext', $platform);

        static::assertNotSame('plaintext', $result);
        static::assertStringStartsWith('<ENC>', (string)$result);
    }

    public function testConvertToPHPValueDecryptsValue(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $encrypted = $this->encryptor->encrypt('plaintext');
        $result = $this->type->convertToPHPValue($encrypted, $platform);

        static::assertSame('plaintext', $result);
    }

    public function testConvertToDatabaseValueNullReturnsNull(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        static::assertNull($this->type->convertToDatabaseValue(null, $platform));
    }

    public function testConvertToPHPValueNullReturnsNull(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        static::assertNull($this->type->convertToPHPValue(null, $platform));
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

    public function testGetNameReturnsFullName(): void
    {
        static::assertSame(AES256FixedType::getFullName(), $this->type->getName());
    }

    public function testRoundTripThroughType(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $encrypted = $this->type->convertToDatabaseValue('original', $platform);
        $decrypted = $this->type->convertToPHPValue($encrypted, $platform);

        static::assertSame('original', $decrypted);
    }

    public function testEncryptIsDeterministic(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $first = $this->type->convertToDatabaseValue('same-value', $platform);
        $second = $this->type->convertToDatabaseValue('same-value', $platform);

        static::assertSame($first, $second);
    }
}
