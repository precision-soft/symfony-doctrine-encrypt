<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\DBAL\Types\Type;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;

/**
 * Extended tests for EncryptorFactory covering additional branches.
 *
 * @internal
 */
final class EncryptorFactoryExtendedTest extends TestCase
{
    public function testFakeEncryptorAlwaysIncludedEvenWithEnabledFilter(): void
    {
        $salt = \str_repeat('f', 32);

        $encryptorFactory = new EncryptorFactory(
            [
                new AES256Encryptor($salt),
                new AES256FixedEncryptor($salt),
                new FakeEncryptor(),
            ],
            [AES256Encryptor::class],
        );

        // Only AES256Encryptor + FakeEncryptor should be included.
        $encryptors = $encryptorFactory->getEncryptors();

        static::assertCount(2, $encryptors);
        static::assertArrayHasKey(AES256Encryptor::class, $encryptors);
        static::assertArrayHasKey(FakeEncryptor::class, $encryptors);
        static::assertArrayNotHasKey(AES256FixedEncryptor::class, $encryptors);
    }

    public function testEmptyEnabledEncryptorsIncludesAll(): void
    {
        $salt = \str_repeat('f', 32);

        $encryptorFactory = new EncryptorFactory(
            [
                new AES256Encryptor($salt),
                new AES256FixedEncryptor($salt),
                new FakeEncryptor(),
            ],
            [],
        );

        static::assertCount(3, $encryptorFactory->getEncryptors());
    }

    public function testGetTypeReturnsAbstractTypeInstance(): void
    {
        $salt = \str_repeat('f', 32);
        $typeName = AES256Type::getFullName();

        // Ensure the Doctrine type is registered.
        if (false === Type::hasType($typeName)) {
            Type::addType($typeName, AES256Type::class);
        }

        $encryptorFactory = new EncryptorFactory([
            new AES256Encryptor($salt),
        ]);

        $abstractType = $encryptorFactory->getType($typeName);

        static::assertInstanceOf(AbstractType::class, $abstractType);
    }

    public function testEncryptorWithNullTypeNameStillRegistered(): void
    {
        $encryptorFactory = new EncryptorFactory([
            new FakeEncryptor(),
        ]);

        static::assertCount(1, $encryptorFactory->getEncryptors());
        static::assertSame([], $encryptorFactory->getTypeNames());
    }

    public function testGetEncryptorByTypeIteratesThroughAllEncryptors(): void
    {
        $salt = \str_repeat('f', 32);

        $encryptorFactory = new EncryptorFactory([
            new FakeEncryptor(),
            new AES256Encryptor($salt),
        ]);

        // Should skip FakeEncryptor (typeName is null) and find AES256Encryptor.
        $encryptor = $encryptorFactory->getEncryptorByType(AES256Type::getFullName());

        static::assertInstanceOf(AES256Encryptor::class, $encryptor);
    }
}
