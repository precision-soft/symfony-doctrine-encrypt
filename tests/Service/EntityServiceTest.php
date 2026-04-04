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
        $class = 'class';
        $field = 'field';
        $salt = \uniqid(\uniqid(\uniqid('', true), true), true);

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
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        $encryptor = $entityService->getEncryptor($class, $field);

        static::assertInstanceOf(EncryptorInterface::class, $encryptor);
    }

    public function testHasEncryptor(): void
    {
        $class = 'class';
        $field = 'field';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        $hasEncryptor = $entityService->hasEncryptor($class, $field);

        static::assertSame(true, $hasEncryptor);
    }

    public function testEncryptDecrypt(): void
    {
        $data = 'data';
        $class = 'class';
        $field = 'field';
        $aes256Encryptor = new Aes256Encryptor(\uniqid(\uniqid(\uniqid('', true), true), true));

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
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        $encryptedData = $entityService->encrypt($data, $class, $field);
        $decryptedData = $aes256Encryptor->decrypt($encryptedData);

        static::assertSame($data, $decryptedData);
    }

    public function testDecrypt(): void
    {
        $class = 'class';
        $field = 'field';
        $aes256Encryptor = new Aes256Encryptor(\uniqid(\uniqid(\uniqid('', true), true), true));
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
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        $decrypted = $entityService->decrypt($encrypted, $class, $field);

        static::assertSame('secret', $decrypted);
    }

    public function testIsEncryptedWithObject(): void
    {
        $field = 'field';
        $entity = new stdClass();
        $class = $entity::class;

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        static::assertSame(true, $entityService->isEncrypted($entity, $field));
    }

    public function testIsEncryptedReturnsFalseForNonEncryptedField(): void
    {
        $class = 'class';
        $field = 'field';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        static::assertSame(false, $entityService->isEncrypted($class, $field));
    }

    public function testGetEncryptorThrowsFieldNotEncryptedException(): void
    {
        $class = 'class';
        $field = 'nonEncryptedField';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
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
            ->with($class)
            ->andReturn($classMetadataMock);

        $this->expectException(FieldNotEncryptedException::class);

        $entityService->getEncryptor($class, $field);
    }

    public function testGetEntitiesWithEncryption(): void
    {
        $field = 'field';

        /** @var EntityService|MockInterface $entityService */
        $entityService = $this->get(EntityService::class);

        $encryptorFactoryMock = $this->get(EncryptorFactory::class);
        $encryptorFactoryMock->shouldReceive('getTypeNames')
            ->once()
            ->andReturn([Aes256Type::getFullName()]);

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$field]);
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

        static::assertSame(true, \is_array($entities));
    }
}
