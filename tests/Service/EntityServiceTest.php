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
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\FieldNotEncryptedException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
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
        $className = stdClass::class;
        $fieldName = 'field';
        $salt = \str_repeat('x', 32);

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
        $className = stdClass::class;
        $fieldName = 'field';

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
        $className = stdClass::class;
        $fieldName = 'field';
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('x', 32));

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
        $className = stdClass::class;
        $fieldName = 'field';
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('x', 32));
        $encrypted = $aes256Encryptor->encrypt('secret');

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
        $className = stdClass::class;
        $fieldName = 'field';

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
        $className = stdClass::class;
        $fieldName = 'nonEncryptedField';

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

    public function testUnknownClassIsRejectedRatherThanReachingDoctrine(): void
    {
        $entityService = $this->get(EntityService::class);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('cannot resolve encrypted fields for unknown class `App\Entity\NoSuchEntity`');

        $entityService->hasEncryptor('App\Entity\NoSuchEntity', 'field');
    }

    public function testTheEncryptedFieldCacheIsKeyedByTheEntityClass(): void
    {
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->twice()
            ->andReturn([Aes256Type::getFullName()]);

        $encryptedClassMetadata = Mockery::mock(ClassMetadata::class);
        $encryptedClassMetadata->shouldReceive('getFieldNames')
            ->once()
            ->andReturn(['secretField']);
        $encryptedClassMetadata->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn(Aes256Type::getFullName());

        $plainClassMetadata = Mockery::mock(ClassMetadata::class);
        $plainClassMetadata->shouldReceive('getFieldNames')
            ->once()
            ->andReturn(['secretField']);
        $plainClassMetadata->shouldReceive('getTypeOfField')
            ->once()
            ->andReturn('string');

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with(EncryptedSubject::class)
            ->andReturn($encryptedClassMetadata);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with(stdClass::class)
            ->andReturn($plainClassMetadata);

        $entityManagerMock = $this->get(EntityManagerInterface::class);
        $entityManagerMock->shouldReceive('getMetadataFactory')
            ->twice()
            ->andReturn($classMetadataFactory);

        static::assertTrue($entityService->hasEncryptor(EncryptedSubject::class, 'secretField'));
        static::assertFalse($entityService->hasEncryptor(stdClass::class, 'secretField'));
    }
}
