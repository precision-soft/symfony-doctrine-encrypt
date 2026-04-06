<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Mockery;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;

/**
 * @internal
 */
final class Aes256TypeTest extends AbstractTestCase
{
    private Aes256Type $aes256Type;
    private Aes256Encryptor $aes256Encryptor;

    public static function getMockDto(): MockDto
    {
        return new MockDto(Aes256Type::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (false === Type::hasType(Aes256Type::getFullName())) {
            Type::addType(Aes256Type::getFullName(), Aes256Type::class);
        }

        /** @var Aes256Type $aes256Type */
        $aes256Type = Type::getType(Aes256Type::getFullName());
        $this->aes256Type = $aes256Type;
        $this->aes256Encryptor = new Aes256Encryptor(\str_repeat('c', 32));
        $this->aes256Type->setEncryptor($this->aes256Encryptor);
    }

    public function testConvertToDatabaseValueEncryptsValue(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $result = $this->aes256Type->convertToDatabaseValue('plaintext', $platform);

        static::assertNotSame('plaintext', $result);
        static::assertStringStartsWith('<ENC>', (string)$result);
    }

    public function testConvertToPHPValueDecryptsValue(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $encrypted = $this->aes256Encryptor->encrypt('plaintext');
        $result = $this->aes256Type->convertToPHPValue($encrypted, $platform);

        static::assertSame('plaintext', $result);
    }

    public function testConvertToDatabaseValueNullReturnsNull(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        static::assertNull($this->aes256Type->convertToDatabaseValue(null, $platform));
    }

    public function testConvertToPHPValueNullReturnsNull(): void
    {
        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        static::assertNull($this->aes256Type->convertToPHPValue(null, $platform));
    }

    public function testConvertWithoutEncryptorThrowsException(): void
    {
        if (false === Type::hasType('encryptedAes256_test')) {
            Type::addType('encryptedAes256_test', Aes256Type::class);
        }

        /** @var Aes256Type $bareType */
        $bareType = Type::getType('encryptedAes256_test');

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

        $encrypted = $this->aes256Type->convertToDatabaseValue('original', $platform);
        $decrypted = $this->aes256Type->convertToPHPValue($encrypted, $platform);

        static::assertSame('original', $decrypted);
    }
}
