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
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;

/**
 * Tests for AbstractType methods not covered by concrete type tests.
 *
 * @internal
 */
final class AbstractTypeTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testGetEncryptorReturnsConfiguredEncryptor(): void
    {
        if (false === Type::hasType(AES256Type::getFullName())) {
            Type::addType(AES256Type::getFullName(), AES256Type::class);
        }

        /** @var AES256Type $aes256Type */
        $aes256Type = Type::getType(AES256Type::getFullName());
        $aes256Encryptor = new AES256Encryptor(\str_repeat('g', 32));
        $aes256Type->setEncryptor($aes256Encryptor);

        static::assertSame($aes256Encryptor, $aes256Type->getEncryptor());
    }

    public function testGetEncryptorWithoutSettingItThrowsException(): void
    {
        if (false === Type::hasType('encryptedAES256_getencryptor_test')) {
            Type::addType('encryptedAES256_getencryptor_test', AES256Type::class);
        }

        /** @var AES256Type $bareType */
        $bareType = Type::getType('encryptedAES256_getencryptor_test');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the encryptor was not set');

        $bareType->getEncryptor();
    }

    public function testSetEncryptorReturnsSelf(): void
    {
        if (false === Type::hasType(AES256Type::getFullName())) {
            Type::addType(AES256Type::getFullName(), AES256Type::class);
        }

        /** @var AES256Type $aes256Type */
        $aes256Type = Type::getType(AES256Type::getFullName());
        $aes256Encryptor = new AES256Encryptor(\str_repeat('h', 32));

        $returnedAbstractType = $aes256Type->setEncryptor($aes256Encryptor);

        static::assertSame($aes256Type, $returnedAbstractType);
    }

    public function testConvertToPHPValueWithoutEncryptorThrowsException(): void
    {
        if (false === Type::hasType('encryptedAES256_phpval_test')) {
            Type::addType('encryptedAES256_phpval_test', AES256Type::class);
        }

        /** @var AES256Type $bareType */
        $bareType = Type::getType('encryptedAES256_phpval_test');

        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the encryptor was not set');

        $bareType->convertToPHPValue('some-value', $platform);
    }

    public function testGetFullNameForAES256Type(): void
    {
        static::assertSame('encryptedAES256', AES256Type::getFullName());
    }

    public function testGetFullNameForAES256FixedType(): void
    {
        static::assertSame('encryptedAES256fixed', AES256FixedType::getFullName());
    }
}
