<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\DBAL\Types\Type;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

/** @internal */
final class EncryptorFactoryExtendedTest extends TestCase
{
    public function testFakeEncryptorAlwaysIncludedEvenWithEnabledFilter(): void
    {
        $salt = \str_repeat('f', 32);

        $encryptorFactory = new EncryptorFactory(
            [
                new Aes256Encryptor($salt),
                new Aes256FixedEncryptor($salt),
                new FakeEncryptor(),
            ],
            [Aes256Encryptor::class],
        );

        $encryptors = $encryptorFactory->getEncryptors();

        static::assertCount(2, $encryptors);
        static::assertArrayHasKey(Aes256Encryptor::class, $encryptors);
        static::assertArrayHasKey(FakeEncryptor::class, $encryptors);
        static::assertArrayNotHasKey(Aes256FixedEncryptor::class, $encryptors);
    }

    public function testEmptyEnabledEncryptorsIncludesAll(): void
    {
        $salt = \str_repeat('f', 32);

        $encryptorFactory = new EncryptorFactory(
            [
                new Aes256Encryptor($salt),
                new Aes256FixedEncryptor($salt),
                new FakeEncryptor(),
            ],
            [],
        );

        static::assertCount(3, $encryptorFactory->getEncryptors());
    }

    public function testGetTypeReturnsAbstractTypeInstance(): void
    {
        $salt = \str_repeat('f', 32);
        $typeName = Aes256Type::getFullName();

        if (false === Type::hasType($typeName)) {
            Type::addType($typeName, Aes256Type::class);
        }

        $encryptorFactory = new EncryptorFactory([
            new Aes256Encryptor($salt),
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
            new Aes256Encryptor($salt),
        ]);

        $encryptor = $encryptorFactory->getEncryptorByType(Aes256Type::getFullName());

        static::assertInstanceOf(Aes256Encryptor::class, $encryptor);
    }
}
