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
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\FieldNotEncryptedException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\Mock\ManagerRegistryMock;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;
use stdClass;

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
        $className = 'class';
        $fieldName = 'field';
        $salt = \str_repeat('x', 32);

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);
        $encryptorFactoryMock->shouldReceive('getEncryptorByType')
            ->once()
            ->andReturn(new Aes256Encryptor($salt));

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        $encryptor = $entityService->getEncryptor($className, $fieldName);

        static::assertInstanceOf(EncryptorInterface::class, $encryptor);
    }

    public function testHasEncryptor(): void
    {
        $className = 'class';
        $fieldName = 'field';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        $hasEncryptor = $entityService->hasEncryptor($className, $fieldName);

        static::assertSame(true, $hasEncryptor);
    }

    public function testEncryptDecrypt(): void
    {
        $data = 'data';
        $className = 'class';
        $fieldName = 'field';
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('x', 32));

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);
        $encryptorFactoryMock->shouldReceive('getEncryptorByType')
            ->once()
            ->andReturn($aes256Encryptor);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        $encryptedData = $entityService->encrypt($data, $className, $fieldName);
        $decryptedData = $aes256Encryptor->decrypt($encryptedData);

        static::assertSame($data, $decryptedData);
    }

    public function testDecrypt(): void
    {
        $className = 'class';
        $fieldName = 'field';
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('x', 32));
        $encrypted = $aes256Encryptor->encrypt('secret');

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);
        $encryptorFactoryMock->shouldReceive('getEncryptorByType')
            ->once()
            ->andReturn($aes256Encryptor);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        $decrypted = $entityService->decrypt($encrypted, $className, $fieldName);

        static::assertSame('secret', $decrypted);
    }

    public function testHasEncryptionWithObject(): void
    {
        $fieldName = 'field';
        $entity = new stdClass();
        $className = $entity::class;

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        static::assertSame(true, $entityService->hasEncryption($entity, $fieldName));
    }

    public function testHasEncryptionReturnsFalseForNonEncryptedField(): void
    {
        $className = 'class';
        $fieldName = 'field';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn('string');

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        static::assertSame(false, $entityService->hasEncryption($className, $fieldName));
    }

    public function testGetEncryptorThrowsFieldNotEncryptedException(): void
    {
        $className = 'class';
        $fieldName = 'nonEncryptedField';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn('string');

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadataMock);

        $this->expectException(FieldNotEncryptedException::class);

        $entityService->getEncryptor($className, $fieldName);
    }

    public function testGetEntitiesWithEncryption(): void
    {
        $fieldName = 'field';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());
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

        $entities = $entityService->getEntitiesWithEncryption();

        static::assertCount(1, $entities);
        static::assertArrayHasKey('test', $entities);
        static::assertInstanceOf(EntityMetadataDto::class, $entities['test']);
    }
}
