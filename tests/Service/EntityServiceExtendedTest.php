<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Query\QueryBuilder as DbalQueryBuilder;
use Doctrine\DBAL\Result;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use Doctrine\ORM\Mapping\ClassMetadataFactory;
use Doctrine\ORM\QueryBuilder as OrmQueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use Mockery\MockInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\NonDeterministicEncryptorException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;
use stdClass;

/** @internal */
final class EntityServiceExtendedTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        return new MockDto(stdClass::class);
    }

    private string $salt;
    private Aes256Encryptor $aes256Encryptor;
    private Aes256FixedEncryptor $aes256FixedEncryptor;

    protected function setUp(): void
    {
        $this->salt = \str_repeat('e', 32);
        $this->aes256Encryptor = new Aes256Encryptor($this->salt);
        $this->aes256FixedEncryptor = new Aes256FixedEncryptor($this->salt);
    }

    public function testHasEncryptedValueReturnsTrueForEncryptedValue(): void
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

        static::assertSame(true, $entityService->hasEncryptedValue($entity, 'secretField'));
    }

    public function testHasEncryptedValueReturnsFalseForPlainValue(): void
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

        static::assertSame(false, $entityService->hasEncryptedValue($entity, 'secretField'));
    }

    public function testHasEncryptedValueReturnsFalseForNullValue(): void
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

        static::assertSame(false, $entityService->hasEncryptedValue($entity, 'secretField'));
    }

    public function testHasEncryptedValueReturnsFalseForEmptyString(): void
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

        static::assertSame(false, $entityService->hasEncryptedValue($entity, 'secretField'));
    }

    public function testHasEncryptedValueWithCompositeIdentifier(): void
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

        static::assertSame(true, $entityService->hasEncryptedValue($entity, 'secretField'));
    }

    public function testSetEncryptedParameterSetsEncryptedValueOnQueryBuilder(): void
    {
        $className = 'App\\Entity\\User';
        $fieldName = 'email';
        $plaintext = 'user@example.com';

        $encryptorFactory = $this->createEncryptorFactoryMock(
            [Aes256FixedType::getFullName()],
            $this->aes256FixedEncryptor,
        );

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getFieldNames')
            ->andReturn([$fieldName]);
        $classMetadata->shouldReceive('getTypeOfField')
            ->with($fieldName)
            ->andReturn(Aes256FixedType::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->with($className)
            ->andReturn($classMetadata);

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
            $className,
            $fieldName,
            $plaintext,
        );
    }

    public function testSetEncryptedParameterWithCustomManager(): void
    {
        $className = 'App\\Entity\\User';
        $fieldName = 'email';
        $plaintext = 'user@example.com';
        $managerName = 'custom_manager';

        $encryptorFactory = $this->createEncryptorFactoryMock(
            [Aes256FixedType::getFullName()],
            $this->aes256FixedEncryptor,
        );

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getFieldNames')
            ->andReturn([$fieldName]);
        $classMetadata->shouldReceive('getTypeOfField')
            ->with($fieldName)
            ->andReturn(Aes256FixedType::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->with($className)
            ->andReturn($classMetadata);

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
            $className,
            $fieldName,
            $plaintext,
            $managerName,
        );
    }

    public function testSetEncryptedParameterThrowsWhenEncryptorIsNotDeterministic(): void
    {
        $className = 'App\\Entity\\User';
        $fieldName = 'email';

        $encryptorFactory = $this->createEncryptorFactoryMock(
            [Aes256Type::getFullName()],
            $this->aes256Encryptor,
        );

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getFieldNames')
            ->andReturn([$fieldName]);
        $classMetadata->shouldReceive('getTypeOfField')
            ->with($fieldName)
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->with($className)
            ->andReturn($classMetadata);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getMetadataFactory')
            ->andReturn($classMetadataFactory);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')
            ->with(null)
            ->andReturn($entityManager);

        $entityService = new EntityService($managerRegistry, $encryptorFactory);

        $ormQueryBuilder = Mockery::mock(OrmQueryBuilder::class);

        $this->expectException(NonDeterministicEncryptorException::class);

        $entityService->setEncryptedParameter(
            $ormQueryBuilder,
            'param',
            $className,
            $fieldName,
            'plaintext',
        );
    }

    public function testGetEncryptedFieldsCachedOnRepeatedLookup(): void
    {
        $className = 'App\\Entity\\User';
        $fieldName = 'email';

        $encryptorFactory = $this->createEncryptorFactoryMock(
            [Aes256Type::getFullName()],
            $this->aes256Encryptor,
        );

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getFieldNames')
            ->once()
            ->andReturn([$fieldName]);
        $classMetadata->shouldReceive('getTypeOfField')
            ->once()
            ->with($fieldName)
            ->andReturn(Aes256Type::getFullName());

        $classMetadataFactory = Mockery::mock(ClassMetadataFactory::class);
        $classMetadataFactory->shouldReceive('getMetadataFor')
            ->once()
            ->with($className)
            ->andReturn($classMetadata);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getMetadataFactory')
            ->once()
            ->andReturn($classMetadataFactory);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')
            ->once()
            ->with(null)
            ->andReturn($entityManager);

        $entityService = new EntityService($managerRegistry, $encryptorFactory);

        $entityService->hasEncryptor($className, $fieldName);
        $entityService->hasEncryptor($className, $fieldName);
        $entityService->hasEncryptor($className, $fieldName);

        static::assertSame(true, $entityService->hasEncryptor($className, $fieldName));
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

        foreach ($identifiers as $identifierField => $identifierValue) {
            $ormClassMetadata->shouldReceive('getColumnName')
                ->with($identifierField)
                ->andReturn($identifierField);
        }

        $platform = Mockery::mock(AbstractPlatform::class);
        $platform->shouldReceive('quoteSingleIdentifier')
            ->andReturnUsing(static fn(string $name): string => '"' . $name . '"');

        $quotedColumnName = '"' . $columnName . '"';
        $quotedTableName = '"' . $tableName . '"';

        $result = Mockery::mock(Result::class);
        $result->shouldReceive('fetchOne')
            ->once()
            ->andReturn($rawDbValue);

        $dbalQueryBuilder = Mockery::mock(DbalQueryBuilder::class);
        $dbalQueryBuilder->shouldReceive('select')
            ->with($quotedColumnName)
            ->andReturnSelf();
        $dbalQueryBuilder->shouldReceive('from')
            ->with($quotedTableName)
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
        $connection->shouldReceive('getDatabasePlatform')
            ->andReturn($platform);

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
