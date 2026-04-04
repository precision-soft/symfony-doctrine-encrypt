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
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

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
        if (false === Type::hasType(Aes256Type::getFullName())) {
            Type::addType(Aes256Type::getFullName(), Aes256Type::class);
        }

        /** @var Aes256Type $aes256Type */
        $aes256Type = Type::getType(Aes256Type::getFullName());
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('g', 32));
        $aes256Type->setEncryptor($aes256Encryptor);

        static::assertSame($aes256Encryptor, $aes256Type->getEncryptor());
    }

    public function testGetEncryptorWithoutSettingItThrowsException(): void
    {
        if (false === Type::hasType('encryptedAes256_getencryptor_test')) {
            Type::addType('encryptedAes256_getencryptor_test', Aes256Type::class);
        }

        /** @var Aes256Type $bareType */
        $bareType = Type::getType('encryptedAes256_getencryptor_test');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the encryptor was not set');

        $bareType->getEncryptor();
    }

    public function testSetEncryptorReturnsSelf(): void
    {
        if (false === Type::hasType(Aes256Type::getFullName())) {
            Type::addType(Aes256Type::getFullName(), Aes256Type::class);
        }

        /** @var Aes256Type $aes256Type */
        $aes256Type = Type::getType(Aes256Type::getFullName());
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('h', 32));

        $returnedAbstractType = $aes256Type->setEncryptor($aes256Encryptor);

        static::assertSame($aes256Type, $returnedAbstractType);
    }

    public function testConvertToPHPValueWithoutEncryptorThrowsException(): void
    {
        if (false === Type::hasType('encryptedAes256_phpval_test')) {
            Type::addType('encryptedAes256_phpval_test', Aes256Type::class);
        }

        /** @var Aes256Type $bareType */
        $bareType = Type::getType('encryptedAes256_phpval_test');

        /** @var AbstractPlatform $platform */
        $platform = Mockery::mock(AbstractPlatform::class);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the encryptor was not set');

        $bareType->convertToPHPValue('some-value', $platform);
    }

    public function testGetFullNameForAes256Type(): void
    {
        static::assertSame('encryptedAes256', Aes256Type::getFullName());
    }

    public function testGetFullNameForAes256FixedType(): void
    {
        static::assertSame('encryptedAes256fixed', Aes256FixedType::getFullName());
    }
}
