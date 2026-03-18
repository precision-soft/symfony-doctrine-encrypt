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
        /** @var EncryptorFactory|MockInterface $mock */
        $mock = $this->get(EncryptorFactory::class);

        $encryptor = $mock->getEncryptor(AES256FixedEncryptor::class);

        static::assertInstanceOf(AES256FixedEncryptor::class, $encryptor);
    }

    public function testGetEncryptorByType(): void
    {
        /** @var EncryptorFactory|MockInterface $mock */
        $mock = $this->get(EncryptorFactory::class);

        $encryptor = $mock->getEncryptorByType(AES256Type::getFullName());

        static::assertInstanceOf(AES256Encryptor::class, $encryptor);
    }

    public function testGetType(): void
    {
        /** @var EncryptorFactory|MockInterface $mock */
        $mock = $this->get(EncryptorFactory::class);

        Type::addType(AES256Type::getFullName(), AES256Type::class);

        $type = $mock->getType(AES256Type::getFullName());

        static::assertInstanceOf(AES256Type::class, $type);
    }

    public function testGetEncryptors(): void
    {
        /** @var EncryptorFactory $mock */
        $mock = $this->get(EncryptorFactory::class);

        static::assertIsArray($mock->getEncryptors());
        static::assertNotEmpty($mock->getEncryptors());
    }

    public function testGetTypeNames(): void
    {
        /** @var EncryptorFactory $mock */
        $mock = $this->get(EncryptorFactory::class);

        static::assertIsArray($mock->getTypeNames());
        static::assertNotEmpty($mock->getTypeNames());
    }

    public function testGetEncryptorThrowsNotFoundException(): void
    {
        /** @var EncryptorFactory $mock */
        $mock = $this->get(EncryptorFactory::class);

        $this->expectException(EncryptorNotFoundException::class);

        $mock->getEncryptor('NonExistentEncryptorClass');
    }

    public function testGetEncryptorByTypeThrowsNotFoundException(): void
    {
        /** @var EncryptorFactory $mock */
        $mock = $this->get(EncryptorFactory::class);

        $this->expectException(EncryptorNotFoundException::class);

        $mock->getEncryptorByType('nonExistentType');
    }

    public function testGetTypeThrowsTypeNotFoundException(): void
    {
        /** @var EncryptorFactory $mock */
        $mock = $this->get(EncryptorFactory::class);

        $this->expectException(TypeNotFoundException::class);

        $mock->getType('nonExistentType');
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

        $factory = new EncryptorFactory(
            [
                new AES256Encryptor($salt),
                new AES256FixedEncryptor($salt),
            ],
            [AES256Encryptor::class],
        );

        static::assertCount(1, $factory->getEncryptors());
        static::assertArrayHasKey(AES256Encryptor::class, $factory->getEncryptors());
    }

    public function testEnabledEncryptorsFilteringSkipsFakeEncryptor(): void
    {
        $salt = \str_repeat('a', 32);

        $factory = new EncryptorFactory(
            [
                new AES256Encryptor($salt),
                new FakeEncryptor(),
            ],
            [AES256Encryptor::class],
        );

        static::assertCount(1, $factory->getEncryptors());
    }
}
