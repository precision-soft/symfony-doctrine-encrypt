<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\ClassMetadataFactory;
use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use Mockery\MockInterface;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;
use PrecisionSoft\Symfony\Phpunit\Mock\ManagerRegistryMock;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;

/**
 * @internal
 */
final class EntityServiceTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        return new MockDto(
            EntityService::class,
            [
                ManagerRegistryMock::class,
                new MockDto(EncryptorFactory::class),
            ],
            true,
        );
    }

    public function testGetEncryptor(): void
    {
        $class = 'class';
        $field = 'field';
        $salt = \uniqid(\uniqid(\uniqid('', true), true), true);

        /** @var EntityService|MockInterface $mock */
        $mock = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([AES256Type::getFullName()]);
        $encryptorFactoryMock->shouldReceive('getEncryptorByType')
            ->once()
            ->andReturn(new AES256Encryptor($salt));

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(AES256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($class)
            ->andReturn($classMetadataMock);

        $encryptor = $mock->getEncryptor($class, $field);

        static::assertInstanceOf(EncryptorInterface::class, $encryptor);
    }

    public function testHasEncryptor(): void
    {
        $class = 'class';
        $field = 'field';

        /** @var EntityService|MockInterface $mock */
        $mock = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([AES256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(AES256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($class)
            ->andReturn($classMetadataMock);

        $hasEncryptor = $mock->hasEncryptor($class, $field);

        static::assertTrue($hasEncryptor);
    }

    public function testEncryptDecrypt(): void
    {
        $data = 'data';
        $class = 'class';
        $field = 'field';
        $encryptor = new AES256Encryptor(\uniqid(\uniqid(\uniqid('', true), true), true));

        /** @var EntityService|MockInterface $mock */
        $mock = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([AES256Type::getFullName()]);
        $encryptorFactoryMock->shouldReceive('getEncryptorByType')
            ->once()
            ->andReturn($encryptor);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(AES256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($class)
            ->andReturn($classMetadataMock);

        $encryped = $mock->encrypt($data, $class, $field);
        $dencryped = $encryptor->decrypt($encryped);

        static::assertSame($data, $dencryped);
    }

    public function testGetEntitiesWithEncryption(): void
    {
        $field = 'field';

        /** @var EntityService|MockInterface $mock */
        $mock = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([AES256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(AES256Type::getFullName());
        $classMetadataMock->shouldReceive('getName')
            ->once()
            ->andReturn('test');

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getAllMetadata')
            ->once()
            ->andReturn([$classMetadataMock]);

        $entites = $mock->getEntitiesWithEncryption();

        static::assertIsArray($entites);
    }
}
