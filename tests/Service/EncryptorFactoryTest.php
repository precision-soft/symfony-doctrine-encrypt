<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\DBAL\Types\Type;
use Mockery\MockInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\DuplicateEncryptorException;
use PrecisionSoft\Doctrine\Encrypt\Exception\EncryptorNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;

/**
 * @internal
 */
final class EncryptorFactoryTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        $salt = \str_repeat('x', 32);

        $encryptors = [
            new Aes256Encryptor($salt),
            new Aes256FixedEncryptor($salt),
            new FakeEncryptor(),
        ];

        return new MockDto(
            EncryptorFactory::class,
            [$encryptors],
            true,
        );
    }

    public function testGetEncryptor(): void
    {
        /** @var EncryptorFactory|MockInterface $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        $encryptor = $encryptorFactory->getEncryptor(Aes256FixedEncryptor::class);

        static::assertInstanceOf(Aes256FixedEncryptor::class, $encryptor);
    }

    public function testGetEncryptorByType(): void
    {
        /** @var EncryptorFactory|MockInterface $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        $encryptor = $encryptorFactory->getEncryptorByType(Aes256Type::getFullName());

        static::assertInstanceOf(Aes256Encryptor::class, $encryptor);
    }

    public function testGetType(): void
    {
        /** @var EncryptorFactory|MockInterface $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        if (false === Type::hasType(Aes256Type::getFullName())) {
            Type::addType(Aes256Type::getFullName(), Aes256Type::class);
        }

        $abstractType = $encryptorFactory->getType(Aes256Type::getFullName());

        static::assertInstanceOf(Aes256Type::class, $abstractType);
    }

    public function testGetEncryptors(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        static::assertIsArray($encryptorFactory->getEncryptors());
        static::assertNotEmpty($encryptorFactory->getEncryptors());
    }

    public function testGetTypeNames(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        static::assertIsArray($encryptorFactory->getTypeNames());
        static::assertNotEmpty($encryptorFactory->getTypeNames());
    }

    public function testGetEncryptorThrowsNotFoundException(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        $this->expectException(EncryptorNotFoundException::class);

        $encryptorFactory->getEncryptor('NonExistentEncryptorClass');
    }

    public function testGetEncryptorByTypeThrowsNotFoundException(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        $this->expectException(EncryptorNotFoundException::class);

        $encryptorFactory->getEncryptorByType('nonExistentType');
    }

    public function testGetTypeThrowsTypeNotFoundException(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        $this->expectException(TypeNotFoundException::class);

        $encryptorFactory->getType('nonExistentType');
    }

    public function testDuplicateEncryptorThrowsException(): void
    {
        $salt = \str_repeat('a', 32);

        $this->expectException(DuplicateEncryptorException::class);

        new EncryptorFactory([
            new Aes256Encryptor($salt),
            new Aes256Encryptor($salt),
        ]);
    }

    public function testEnabledEncryptorsFiltering(): void
    {
        $salt = \str_repeat('a', 32);

        $encryptorFactoryInstance = new EncryptorFactory(
            [
                new Aes256Encryptor($salt),
                new Aes256FixedEncryptor($salt),
            ],
            [Aes256Encryptor::class],
        );

        static::assertCount(1, $encryptorFactoryInstance->getEncryptors());
        static::assertArrayHasKey(Aes256Encryptor::class, $encryptorFactoryInstance->getEncryptors());
    }

    public function testEnabledEncryptorsFilteringSkipsFakeEncryptor(): void
    {
        $salt = \str_repeat('a', 32);

        $encryptorFactoryInstance = new EncryptorFactory(
            [
                new Aes256Encryptor($salt),
                new FakeEncryptor(),
            ],
            [Aes256Encryptor::class],
        );

        static::assertCount(2, $encryptorFactoryInstance->getEncryptors());
        static::assertArrayHasKey(Aes256Encryptor::class, $encryptorFactoryInstance->getEncryptors());
        static::assertArrayHasKey(FakeEncryptor::class, $encryptorFactoryInstance->getEncryptors());
    }
}
