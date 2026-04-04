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
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;

/**
 * @internal
 */
final class Aes256FixedTypeTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private Aes256FixedType $aes256FixedType;
    private Aes256FixedEncryptor $aes256FixedEncryptor;

    protected function setUp(): void
    {
        if (false === Type::hasType(Aes256FixedType::getFullName())) {
            Type::addType(Aes256FixedType::getFullName(), Aes256FixedType::class);
        }

        /** @var Aes256FixedType $aes256FixedType */
        $aes256FixedType = Type::getType(Aes256FixedType::getFullName());
        $this->aes256FixedType = $aes256FixedType;
        $this->aes256FixedEncryptor = new Aes256FixedEncryptor(\str_repeat('c', 32));
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
        if (false === Type::hasType('encryptedAes256fixed_test')) {
            Type::addType('encryptedAes256fixed_test', Aes256FixedType::class);
        }

        /** @var Aes256FixedType $bareType */
        $bareType = Type::getType('encryptedAes256fixed_test');

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
