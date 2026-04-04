<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\QueryBuilder as DbalQueryBuilder;
use Doctrine\DBAL\Result;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use Doctrine\ORM\Mapping\ClassMetadataFactory;
use Doctrine\ORM\QueryBuilder as OrmQueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;
use stdClass;

/**
 * Tests for EntityService::isValueEncrypted() and EntityService::setEncryptedParameter().
 *
 * @internal
 */
final class EntityServiceExtendedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private string $salt;
    private Aes256Encryptor $aes256Encryptor;
    private Aes256FixedEncryptor $aes256FixedEncryptor;

    protected function setUp(): void
    {
        $this->salt = \str_repeat('e', 32);
        $this->aes256Encryptor = new Aes256Encryptor($this->salt);
        $this->aes256FixedEncryptor = new Aes256FixedEncryptor($this->salt);
    }

    public function testIsValueEncryptedReturnsTrueForEncryptedValue(): void
    {
        $encryptedValue = $this->aes256Encryptor->encrypt('secret');
        $entity = new stdClass();

        [$entityService,] = $this->createServiceWithDbalMock(
            $entity,
            'secretField',
            'secret_field',
            'my_table',
            ['id' => 42],
            $encryptedValue,
        );

        static::assertSame(true, $entityService->isValueEncrypted($entity, 'secretField'));
    }

    public function testIsValueEncryptedReturnsFalseForPlainValue(): void
    {
        $entity = new stdClass();

        [$entityService,] = $this->createServiceWithDbalMock(
            $entity,
            'secretField',
            'secret_field',
            'my_table',
            ['id' => 42],
            'plain-text-value',
        );

        static::assertSame(false, $entityService->isValueEncrypted($entity, 'secretField'));
    }

    public function testIsValueEncryptedReturnsFalseForNullValue(): void
    {
        $entity = new stdClass();

        [$entityService,] = $this->createServiceWithDbalMock(
            $entity,
            'secretField',
            'secret_field',
            'my_table',
            ['id' => 42],
            null,
        );

        static::assertSame(false, $entityService->isValueEncrypted($entity, 'secretField'));
    }

    public function testIsValueEncryptedReturnsFalseForEmptyString(): void
    {
        $entity = new stdClass();

        [$entityService,] = $this->createServiceWithDbalMock(
            $entity,
            'secretField',
            'secret_field',
            'my_table',
            ['id' => 42],
            '',
        );

        static::assertSame(false, $entityService->isValueEncrypted($entity, 'secretField'));
    }

    public function testIsValueEncryptedWithCompositeIdentifier(): void
    {
        $encryptedValue = $this->aes256Encryptor->encrypt('composite-test');
        $entity = new stdClass();

        [$entityService,] = $this->createServiceWithDbalMock(
            $entity,
            'secretField',
            'secret_field',
            'my_table',
            ['tenantId' => 10, 'userId' => 20],
            $encryptedValue,
        );

        static::assertSame(true, $entityService->isValueEncrypted($entity, 'secretField'));
    }

    public function testSetEncryptedParameterSetsEncryptedValueOnQueryBuilder(): void
    {
        $class = 'App\\Entity\\User';
        $field = 'email';
        $plaintext = 'user@example.com';

        $encryptorFactory = $this->createEncryptorFactoryMock(
            [Aes256FixedType::getFullName()],
            $this->aes256FixedEncryptor,
        );

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->andReturn([$field]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->with($field)
            ->andReturn(Aes256FixedType::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->with($class)
            ->andReturn($classMetadataMock);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getMetadataFactory')
            ->andReturn($classMetadataFactory);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')
            ->with(null)
            ->andReturn($entityManager);

        $entityService = new EntityService($managerRegistry, $encryptorFactory);

        $ormQueryBuilder = Mockery::mock(OrmQueryBuilder::class);
        $expectedEncrypted = $this->aes256FixedEncryptor->encrypt($plaintext);

        $ormQueryBuilder->shouldReceive('setParameter')
            ->once()
            ->with('email_param', $expectedEncrypted)
            ->andReturnSelf();

        $entityService->setEncryptedParameter(
            $ormQueryBuilder,
            'email_param',
            $class,
            $field,
            $plaintext,
        );
    }

    public function testSetEncryptedParameterWithCustomManager(): void
    {
        $class = 'App\\Entity\\User';
        $field = 'email';
        $plaintext = 'user@example.com';
        $managerName = 'custom_manager';

        $encryptorFactory = $this->createEncryptorFactoryMock(
            [Aes256FixedType::getFullName()],
            $this->aes256FixedEncryptor,
        );

        $classMetadataMock = Mockery::mock(ClassMetadata::class);
        $classMetadataMock->shouldReceive('getFieldNames')
            ->andReturn([$field]);
        $classMetadataMock->shouldReceive('getTypeOfField')
            ->with($field)
            ->andReturn(Aes256FixedType::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->with($class)
            ->andReturn($classMetadataMock);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getMetadataFactory')
            ->andReturn($classMetadataFactory);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')
            ->with($managerName)
            ->andReturn($entityManager);

        $entityService = new EntityService($managerRegistry, $encryptorFactory);

        $ormQueryBuilder = Mockery::mock(OrmQueryBuilder::class);
        $expectedEncrypted = $this->aes256FixedEncryptor->encrypt($plaintext);

        $ormQueryBuilder->shouldReceive('setParameter')
            ->once()
            ->with('param', $expectedEncrypted)
            ->andReturnSelf();

        $entityService->setEncryptedParameter(
            $ormQueryBuilder,
            'param',
            $class,
            $field,
            $plaintext,
            $managerName,
        );
    }

    /**
     * @param array<string, mixed> $identifiers
     *
     * @return array{EntityService, Mockery\MockInterface}
     */
    private function createServiceWithDbalMock(
        object $entity,
        string $fieldName,
        string $columnName,
        string $tableName,
        array $identifiers,
        mixed $rawDbValue,
    ): array {
        $ormClassMetadata = Mockery::mock(OrmClassMetadata::class);
        $ormClassMetadata->shouldReceive('getColumnName')
            ->with($fieldName)
            ->andReturn($columnName);
        $ormClassMetadata->shouldReceive('getTableName')
            ->andReturn($tableName);
        $ormClassMetadata->shouldReceive('getIdentifierValues')
            ->with($entity)
            ->andReturn($identifiers);

        foreach ($identifiers as $idField => $idValue) {
            $ormClassMetadata->shouldReceive('getColumnName')
                ->with($idField)
                ->andReturn($idField);
        }

        $result = Mockery::mock(Result::class);
        $result->shouldReceive('fetchOne')
            ->once()
            ->andReturn($rawDbValue);

        $dbalQueryBuilder = Mockery::mock(DbalQueryBuilder::class);
        $dbalQueryBuilder->shouldReceive('select')
            ->with($columnName)
            ->andReturnSelf();
        $dbalQueryBuilder->shouldReceive('from')
            ->with($tableName)
            ->andReturnSelf();
        $dbalQueryBuilder->shouldReceive('andWhere')
            ->andReturnSelf();
        $dbalQueryBuilder->shouldReceive('setParameter')
            ->andReturnSelf();
        $dbalQueryBuilder->shouldReceive('executeQuery')
            ->once()
            ->andReturn($result);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('createQueryBuilder')
            ->once()
            ->andReturn($dbalQueryBuilder);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getClassMetadata')
            ->with($entity::class)
            ->andReturn($ormClassMetadata);
        $entityManager->shouldReceive('getConnection')
            ->andReturn($connection);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')
            ->with(null)
            ->andReturn($entityManager);

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);

        $entityService = new EntityService($managerRegistry, $encryptorFactory);

        return [$entityService, $entityManager];
    }

    private function createEncryptorFactoryMock(
        array $typeNames,
        mixed $encryptor,
    ): MockInterface&EncryptorFactory {
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldReceive('getTypeNames')
            ->andReturn($typeNames);
        $encryptorFactory->shouldReceive('getEncryptorByType')
            ->andReturn($encryptor);

        return $encryptorFactory;
    }
}
