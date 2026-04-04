<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\DBAL\Types\Type;
use Mockery\MockInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\DuplicateEncryptorException;
use PrecisionSoft\Doctrine\Encrypt\Exception\EncryptorNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;

/**
 * @internal
 */
final class EncryptorFactoryTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        $salt = \uniqid(\uniqid(\uniqid('', true), true), true);

        $encryptors = [
            new AES256Encryptor($salt),
            new AES256FixedEncryptor($salt),
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

        $encryptor = $encryptorFactory->getEncryptor(AES256FixedEncryptor::class);

        static::assertInstanceOf(AES256FixedEncryptor::class, $encryptor);
    }

    public function testGetEncryptorByType(): void
    {
        /** @var EncryptorFactory|MockInterface $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        $encryptor = $encryptorFactory->getEncryptorByType(AES256Type::getFullName());

        static::assertInstanceOf(AES256Encryptor::class, $encryptor);
    }

    public function testGetType(): void
    {
        /** @var EncryptorFactory|MockInterface $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        if (false === Type::hasType(AES256Type::getFullName())) {
            Type::addType(AES256Type::getFullName(), AES256Type::class);
        }

        $abstractType = $encryptorFactory->getType(AES256Type::getFullName());

        static::assertInstanceOf(AES256Type::class, $abstractType);
    }

    public function testGetEncryptors(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        static::assertSame(true, \is_array($encryptorFactory->getEncryptors()));
        static::assertSame(true, [] !== $encryptorFactory->getEncryptors());
    }

    public function testGetTypeNames(): void
    {
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->get(EncryptorFactory::class);

        static::assertSame(true, \is_array($encryptorFactory->getTypeNames()));
        static::assertSame(true, [] !== $encryptorFactory->getTypeNames());
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
            new AES256Encryptor($salt),
            new AES256Encryptor($salt),
        ]);
    }

    public function testEnabledEncryptorsFiltering(): void
    {
        $salt = \str_repeat('a', 32);

        $encryptorFactoryInstance = new EncryptorFactory(
            [
                new AES256Encryptor($salt),
                new AES256FixedEncryptor($salt),
            ],
            [AES256Encryptor::class],
        );

        static::assertCount(1, $encryptorFactoryInstance->getEncryptors());
        static::assertArrayHasKey(AES256Encryptor::class, $encryptorFactoryInstance->getEncryptors());
    }

    public function testEnabledEncryptorsFilteringSkipsFakeEncryptor(): void
    {
        $salt = \str_repeat('a', 32);

        $encryptorFactoryInstance = new EncryptorFactory(
            [
                new AES256Encryptor($salt),
                new FakeEncryptor(),
            ],
            [AES256Encryptor::class],
        );

        static::assertCount(2, $encryptorFactoryInstance->getEncryptors());
        static::assertArrayHasKey(AES256Encryptor::class, $encryptorFactoryInstance->getEncryptors());
        static::assertArrayHasKey(FakeEncryptor::class, $encryptorFactoryInstance->getEncryptors());
    }
}
