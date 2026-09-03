<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Command;

use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Doctrine\ORM\UnitOfWork;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseDecryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\CheckpointScopeDto;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\StringableIdentifier;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;
use ReflectionMethod;
use stdClass;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\Console\Tester\CommandTester;

/** @internal */
final class AbstractDatabaseCommandTest extends AbstractTestCase
{
    /** @var string[] */
    private array $checkpointPaths = [];

    public static function getMockDto(): MockDto
    {
        return new MockDto(stdClass::class);
    }

    public function testApplyKeysetPaginationSingleIdentifier(): void
    {
        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $entityService = Mockery::mock(EntityService::class);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $queryBuilder = Mockery::mock(QueryBuilder::class);
        $queryBuilder->shouldReceive('andWhere')
            ->once()
            ->with('e.id > :lastId')
            ->andReturnSelf();
        $queryBuilder->shouldReceive('setParameter')
            ->once()
            ->with('lastId', 42)
            ->andReturnSelf();

        $reflectionMethod = new ReflectionMethod($databaseEncryptCommand, 'applyKeysetPagination');
        $reflectionMethod->invoke($databaseEncryptCommand, $queryBuilder, ['id'], ['id' => 42]);
    }

    public function testApplyKeysetPaginationCompositeIdentifier(): void
    {
        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $entityService = Mockery::mock(EntityService::class);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $queryBuilder = Mockery::mock(QueryBuilder::class);
        $queryBuilder->shouldReceive('setParameter')
            ->once()
            ->with('lastId0', 10)
            ->andReturnSelf();
        $queryBuilder->shouldReceive('setParameter')
            ->once()
            ->with('lastId1', 20)
            ->andReturnSelf();
        $queryBuilder->shouldReceive('andWhere')
            ->once()
            ->andReturnSelf();

        $reflectionMethod = new ReflectionMethod($databaseEncryptCommand, 'applyKeysetPagination');
        $reflectionMethod->invoke(
            $databaseEncryptCommand,
            $queryBuilder,
            ['tenantId', 'userId'],
            ['tenantId' => 10, 'userId' => 20],
        );
    }

    public function testProcessEntitiesWithSingleEntityBatch(): void
    {
        $entity = new stdClass();
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(1);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $firstEntityQuery = Mockery::mock(Query::class);
        $firstEntityQuery->shouldReceive('getResult')->once()->andReturn([$entity]);

        $firstEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $firstEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($firstEntityQuery);

        $secondEntityQuery = Mockery::mock(Query::class);
        $secondEntityQuery->shouldReceive('getResult')->once()->andReturn([]);

        $secondEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $secondEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setParameter')->with('lastId', 1)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($secondEntityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $firstEntityQueryBuilder, $secondEntityQueryBuilder);

        $unitOfWork = Mockery::mock(UnitOfWork::class);
        $unitOfWork->shouldReceive('getOriginalEntityData')->with($entity)->andReturn(['id' => 1, 'email' => 'secret']);
        $unitOfWork->shouldReceive('setOriginalEntityData')->once()->with($entity, ['id' => 1, 'email' => null]);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('persist')->once()->with($entity);
        $entityManager->shouldReceive('flush')->once();
        $entityManager->shouldReceive('clear')->once();

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testProcessEntitiesUsesCustomBatchSize(): void
    {
        $entity = new stdClass();
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(1);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $firstEntityQuery = Mockery::mock(Query::class);
        $firstEntityQuery->shouldReceive('getResult')->once()->andReturn([$entity]);

        $firstEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $firstEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('setMaxResults')->once()->with(2)->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($firstEntityQuery);

        $secondEntityQuery = Mockery::mock(Query::class);
        $secondEntityQuery->shouldReceive('getResult')->once()->andReturn([]);

        $secondEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $secondEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setMaxResults')->once()->with(2)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setParameter')->with('lastId', 1)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($secondEntityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $firstEntityQueryBuilder, $secondEntityQueryBuilder);

        $unitOfWork = Mockery::mock(UnitOfWork::class);
        $unitOfWork->shouldReceive('getOriginalEntityData')->with($entity)->andReturn(['id' => 1, 'email' => 'secret']);
        $unitOfWork->shouldReceive('setOriginalEntityData')->once()->with($entity, ['id' => 1, 'email' => null]);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('persist')->once()->with($entity);
        $entityManager->shouldReceive('flush')->once();
        $entityManager->shouldReceive('clear')->once();

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute(['--batch-size' => '2'], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testInvalidBatchSizeReturnsFailure(): void
    {
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute(['--batch-size' => '0'], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString('batch-size', $commandTester->getDisplay());
    }

    public function testDecryptSwapsFakeEncryptorOnlyAroundFlush(): void
    {
        $entity = new stdClass();
        $className = stdClass::class;
        $typeName = 'encryptedAes256';

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => $typeName]);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(1);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $firstEntityQuery = Mockery::mock(Query::class);
        /* ordered() is the assertion here: the SELECT must run before the FakeEncryptor swap, or plaintext is re-encrypted on write */
        $firstEntityQuery->shouldReceive('getResult')->once()->ordered('select')->andReturn([$entity]);

        $firstEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $firstEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($firstEntityQuery);

        $secondEntityQuery = Mockery::mock(Query::class);
        $secondEntityQuery->shouldReceive('getResult')->once()->andReturn([]);

        $secondEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $secondEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setParameter')->with('lastId', 1)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($secondEntityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $firstEntityQueryBuilder, $secondEntityQueryBuilder);

        $unitOfWork = Mockery::mock(UnitOfWork::class);
        $unitOfWork->shouldReceive('getOriginalEntityData')->with($entity)->andReturn(['id' => 1, 'email' => 'plaintext']);
        $unitOfWork->shouldReceive('setOriginalEntityData')->once()->with($entity, ['id' => 1, 'email' => null]);

        $originalEncryptor = Mockery::mock(EncryptorInterface::class);
        $fakeEncryptor = Mockery::mock(FakeEncryptor::class);

        $abstractType = Mockery::mock(AbstractType::class);
        $abstractType->shouldReceive('getEncryptor')->once()->ordered('select')->andReturn($originalEncryptor);
        $abstractType->shouldReceive('setEncryptor')->once()->ordered('select')->with($fakeEncryptor)->andReturnSelf();
        $abstractType->shouldReceive('setEncryptor')->once()->ordered('select')->with($originalEncryptor)->andReturnSelf();

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('persist')->once()->with($entity);
        $entityManager->shouldReceive('flush')->once();
        $entityManager->shouldReceive('clear')->once();

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldReceive('getType')->with($typeName)->andReturn($abstractType);
        $encryptorFactory->shouldReceive('getEncryptor')->with(FakeEncryptor::class)->andReturn($fakeEncryptor);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([$entityMetadataDto]);

        $databaseDecryptCommand = new DatabaseDecryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseDecryptCommand);

        $commandTester = new CommandTester($databaseDecryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testProcessEntitiesExceptionResetsManager(): void
    {
        $entity = new stdClass();
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(1);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->andReturn($countQuery);

        $entityQuery = Mockery::mock(Query::class);
        $entityQuery->shouldReceive('getResult')->once()->andReturn([$entity]);

        $entityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $entityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $entityQueryBuilder->shouldReceive('getQuery')->andReturn($entityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $entityQueryBuilder);

        $unitOfWork = Mockery::mock(UnitOfWork::class);
        $unitOfWork->shouldReceive('getOriginalEntityData')->with($entity)->andReturn(['id' => 1, 'email' => 'secret']);
        $unitOfWork->shouldReceive('setOriginalEntityData')->once()->with($entity, ['id' => 1, 'email' => null]);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('persist')->once()->with($entity);
        $entityManager->shouldReceive('flush')->once()->andThrow(new Exception('flush failed'));

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);
        $managerRegistry->shouldReceive('resetManager')->once()->with(null);

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldReceive('getTypeNames')->andReturn([]);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $checkpointPath = $this->buildCheckpointPath();

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute(['--checkpoint' => $checkpointPath], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertFileDoesNotExist($checkpointPath);
    }

    public function testABatchThatDoesNotAdvanceTheCursorAborts(): void
    {
        $entity = new stdClass();
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(1);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $firstEntityQuery = Mockery::mock(Query::class);
        $firstEntityQuery->shouldReceive('getResult')->once()->andReturn([$entity]);

        $firstEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $firstEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($firstEntityQuery);

        /* the keyset predicate is applied and the engine still hands the same row back: the loop must stop, never spin */
        $secondEntityQuery = Mockery::mock(Query::class);
        $secondEntityQuery->shouldReceive('getResult')->once()->andReturn([$entity]);

        $secondEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $secondEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setParameter')->with('lastId', 1)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($secondEntityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $firstEntityQueryBuilder, $secondEntityQueryBuilder);

        $unitOfWork = Mockery::mock(UnitOfWork::class);
        $unitOfWork->shouldReceive('getOriginalEntityData')->with($entity)->andReturn(['id' => 1, 'email' => 'secret']);
        $unitOfWork->shouldReceive('setOriginalEntityData')->once()->with($entity, ['id' => 1, 'email' => null]);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('persist')->once()->with($entity);
        $entityManager->shouldReceive('flush')->once();
        $entityManager->shouldReceive('clear')->once();

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')->once()->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, Mockery::mock(EncryptorFactory::class), $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString(
            'the cursor for `stdClass` did not advance past `{"id":1}`; the identifier cannot be paginated on',
            $this->collapseWhitespace($commandTester->getDisplay()),
        );
    }

    public function testALoadFailureNamesTheEntityAndTheCursor(): void
    {
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getTypeOfField')->with('id')->andReturn('integer');

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(3);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $countQueryBuilder->shouldReceive('setParameter')->with('lastId', 42)->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $entityQuery = Mockery::mock(Query::class);
        $entityQuery->shouldReceive('getResult')->once()->andThrow(new Exception('unknown salt version `gone`'));

        $entityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $entityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $entityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('setParameter')->with('lastId', 42)->andReturnSelf();
        $entityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($entityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $entityQueryBuilder);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn(Mockery::mock(UnitOfWork::class));

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);
        $managerRegistry->shouldNotReceive('resetManager');

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')->once()->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, Mockery::mock(EncryptorFactory::class), $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute(['--entity' => $className, '--from-id' => '42'], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString(
            'loading a batch of `stdClass` after the cursor `{"id":42}` failed: unknown salt version `gone`',
            $this->collapseWhitespace($commandTester->getDisplay()),
        );
    }

    public function testRequestedClassNamesDefaultsToEveryEntity(): void
    {
        $databaseEncryptCommand = $this->buildCommand([]);

        static::assertSame([], $this->invoke($databaseEncryptCommand, 'getRequestedClassNames'));
    }

    public function testRequestedClassNamesTrimsWhitespaceAndTheLeadingBackslash(): void
    {
        $databaseEncryptCommand = $this->buildCommand(['--entity' => ' \App\Entity\First ,, App\Entity\Second ']);

        static::assertSame(
            ['App\Entity\First', 'App\Entity\Second'],
            $this->invoke($databaseEncryptCommand, 'getRequestedClassNames'),
        );
    }

    public function testRequestedClassNamesDropsARepeatedClass(): void
    {
        $databaseEncryptCommand = $this->buildCommand(['--entity' => 'App\Entity\First,App\Entity\First']);

        static::assertSame(['App\Entity\First'], $this->invoke($databaseEncryptCommand, 'getRequestedClassNames'));
    }

    public function testAStoredCursorThatMissesAnIdentifierFieldIsRejected(): void
    {
        $checkpointPath = $this->buildCheckpointPath();
        (new CheckpointService($this->buildCheckpointScope(), $checkpointPath))->setIdentifierValues(stdClass::class, ['legacyId' => 5]);

        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $checkpointPath]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the checkpoint cursor for `stdClass` does not address `id`');

        $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $this->buildEntityMetadataDto(stdClass::class));
    }

    public function testKeysetPaginationSkipsAnIdentifierItHasNoValueFor(): void
    {
        $databaseEncryptCommand = $this->buildCommand([]);

        $queryBuilder = Mockery::mock(QueryBuilder::class);
        $queryBuilder->shouldNotReceive('andWhere');
        $queryBuilder->shouldNotReceive('setParameter');

        $this->invoke($databaseEncryptCommand, 'applyKeysetPagination', $queryBuilder, ['id'], []);
        $this->invoke($databaseEncryptCommand, 'applyKeysetPagination', $queryBuilder, ['tenantId', 'userId'], []);
    }

    public function testFilterEntitiesKeepsOnlyTheRequestedClass(): void
    {
        $firstEntityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);
        $secondEntityMetadataDto = $this->buildEntityMetadataDto(EntityMetadataDto::class);

        $databaseEncryptCommand = $this->buildCommand(['--entity' => EntityMetadataDto::class]);

        static::assertSame(
            [$secondEntityMetadataDto],
            $this->invoke($databaseEncryptCommand, 'filterEntities', [$firstEntityMetadataDto, $secondEntityMetadataDto]),
        );
    }

    public function testTheCheckpointIsReadOnceForTheWholeRun(): void
    {
        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $this->buildCheckpointPath()]);

        static::assertSame(
            $this->invoke($databaseEncryptCommand, 'getCheckpointService'),
            $this->invoke($databaseEncryptCommand, 'getCheckpointService'),
        );
    }

    public function testFilterEntitiesAcceptsAClassNameWithALeadingBackslash(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);

        $databaseEncryptCommand = $this->buildCommand(['--entity' => '\\' . stdClass::class]);

        static::assertSame([$entityMetadataDto], $this->invoke($databaseEncryptCommand, 'filterEntities', [$entityMetadataDto]));
    }

    public function testFilterEntitiesRejectsAClassWithoutEncryptedFields(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);

        $databaseEncryptCommand = $this->buildCommand(['--entity' => 'App\Entity\Absent']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('no entity with encrypted fields found for `App\Entity\Absent`');

        $this->invoke($databaseEncryptCommand, 'filterEntities', [$entityMetadataDto]);
    }

    public function testFromIdCastsAnIntegerIdentifier(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['id'], 'integer');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => '42']);

        static::assertSame(
            ['id' => 42],
            $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto),
        );
    }

    public function testFromIdKeepsANonIntegerIdentifierAsAString(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['uuid'], 'string');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => 'ff-01']);

        static::assertSame(
            ['uuid' => 'ff-01'],
            $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto),
        );
    }

    public function testFromIdRejectsANonIntegerForAnIntegerIdentifier(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['id'], 'integer');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => 'not-a-number']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the `--from-id` option must be an integer');

        $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto);
    }

    public function testFromIdRequiresASingleEntity(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['id'], 'integer');

        $databaseEncryptCommand = $this->buildCommand(['--from-id' => '42']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the `--from-id` option requires a single `--entity` with a single identifier field');

        $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto);
    }

    public function testFromIdRequiresASingleIdentifierField(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['tenantId', 'userId'], 'integer');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => '42']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the `--from-id` option requires a single `--entity` with a single identifier field');

        $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto);
    }

    public function testAnOverflowingBatchSizeIsRejected(): void
    {
        $databaseEncryptCommand = $this->buildCommand(['--batch-size' => '99999999999999999999']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the `--batch-size` option must be a positive integer');

        $this->invoke($databaseEncryptCommand, 'getBatchSize');
    }

    public function testTheLargestRepresentableBatchSizeIsAccepted(): void
    {
        $databaseEncryptCommand = $this->buildCommand(['--batch-size' => (string)\PHP_INT_MAX]);

        static::assertSame(\PHP_INT_MAX, $this->invoke($databaseEncryptCommand, 'getBatchSize'));
    }

    public function testFromIdCastsABigintIdentifier(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['id'], 'bigint');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => '42']);

        static::assertSame(
            ['id' => 42],
            $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto),
        );
    }

    public function testFromIdKeepsABigintBeyondPhpIntAsAString(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['id'], 'bigint');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => '99999999999999999999']);

        static::assertSame(
            ['id' => '99999999999999999999'],
            $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto),
        );
    }

    public function testFromIdRejectsANonIntegerForABigintIdentifier(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['id'], 'bigint');

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => '4x2']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the `--from-id` option must be an integer');

        $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto);
    }

    public function testAStoredCursorWithANonScalarValueIsRejected(): void
    {
        $checkpointPath = $this->buildCheckpointPath();
        \file_put_contents($checkpointPath, \json_encode([
            'version' => CheckpointService::FORMAT_VERSION,
            'scope' => $this->buildCheckpointScope()->toArray(),
            'entities' => [stdClass::class => ['id' => ['date' => '2020-01-01']]],
            'completed' => [],
        ]));

        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $checkpointPath]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the checkpoint cursor for `stdClass` holds a value for `id` that is not an integer or a string');

        $this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $this->buildEntityMetadataDto(stdClass::class));
    }

    public function testAStoredCursorIsConvertedThroughTheIdentifierType(): void
    {
        $checkpointPath = $this->buildCheckpointPath();
        \file_put_contents($checkpointPath, \json_encode([
            'version' => CheckpointService::FORMAT_VERSION,
            'scope' => $this->buildCheckpointScope()->toArray(),
            'entities' => [stdClass::class => ['day' => '2020-01-02']],
            'completed' => [],
        ]));

        $platform = Mockery::mock(AbstractPlatform::class);
        $platform->shouldReceive('getDateFormatString')->andReturn('Y-m-d');

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getDatabasePlatform')->andReturn($platform);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getConnection')->andReturn($connection);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $checkpointPath], $managerRegistry);

        $identifierValues = $this->invoke(
            $databaseEncryptCommand,
            'getInitialIdentifierValues',
            $this->buildEntityMetadataDto(stdClass::class, ['day'], 'date_immutable'),
        );

        static::assertIsArray($identifierValues);
        static::assertInstanceOf(DateTimeImmutable::class, $identifierValues['day']);
        static::assertSame('2020-01-02', $identifierValues['day']->format('Y-m-d'));
    }

    public function testFromIdIsConvertedThroughTheIdentifierType(): void
    {
        $platform = Mockery::mock(AbstractPlatform::class);
        $platform->shouldReceive('getDateFormatString')->andReturn('Y-m-d');

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getDatabasePlatform')->andReturn($platform);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getConnection')->andReturn($connection);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => '2020-01-02'], $managerRegistry);

        $identifierValues = $this->invoke(
            $databaseEncryptCommand,
            'getInitialIdentifierValues',
            $this->buildEntityMetadataDto(stdClass::class, ['day'], 'date_immutable'),
        );

        static::assertIsArray($identifierValues);
        static::assertInstanceOf(DateTimeImmutable::class, $identifierValues['day']);
    }

    public function testFromIdThatTheIdentifierTypeCannotConvertIsRejected(): void
    {
        $platform = Mockery::mock(AbstractPlatform::class);
        $platform->shouldReceive('getDateFormatString')->andReturn('Y-m-d');

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('getDatabasePlatform')->andReturn($platform);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getConnection')->andReturn($connection);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $databaseEncryptCommand = $this->buildCommand(['--entity' => stdClass::class, '--from-id' => 'not-a-date'], $managerRegistry);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the identifier value `not-a-date` cannot be converted through the `date_immutable` type of `stdClass::day`');

        $this->invoke(
            $databaseEncryptCommand,
            'getInitialIdentifierValues',
            $this->buildEntityMetadataDto(stdClass::class, ['day'], 'date_immutable'),
        );
    }

    public function testOnBatchProcessedStoresAStringableIdentifierAsAString(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['uuid'], 'guid');
        $checkpointPath = $this->buildCheckpointPath();

        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $checkpointPath]);
        $this->invoke($databaseEncryptCommand, 'onBatchProcessed', $entityMetadataDto, ['uuid' => new StringableIdentifier('ff-01')]);

        static::assertSame(
            ['uuid' => 'ff-01'],
            (new CheckpointService($this->buildCheckpointScope(), $checkpointPath))->getIdentifierValues(stdClass::class),
        );
    }

    public function testOnBatchProcessedRefusesAnIdentifierThatIsNeitherScalarNorStringable(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class, ['day'], 'date_immutable');

        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $this->buildCheckpointPath()]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the identifier `day` of `stdClass` is not an integer, a string or a `Stringable`; a checkpoint cannot address it');

        $this->invoke($databaseEncryptCommand, 'onBatchProcessed', $entityMetadataDto, ['day' => new DateTimeImmutable()]);
    }

    public function testTheCheckpointScopeCarriesTheCommandTheManagerAndTheCurrentSaltVersion(): void
    {
        $saltsByVersion = ['v1' => 'checkpoint-scope-test-salt-value-one', 'v2' => 'checkpoint-scope-test-salt-value-two'];

        $aes256Type = Mockery::mock(Aes256Type::class);
        $aes256Type->shouldReceive('getEncryptor')->andReturn(new Aes256Encryptor($saltsByVersion, 'v2', 'v1'));

        $aes256FixedType = Mockery::mock(Aes256FixedType::class);
        $aes256FixedType->shouldReceive('getEncryptor')->andReturn(new Aes256FixedEncryptor($saltsByVersion, 'v2', 'v1'));

        $customType = Mockery::mock(AbstractType::class);
        $customType->shouldReceive('getEncryptor')->andReturn(Mockery::mock(EncryptorInterface::class));

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldReceive('getTypeNames')->andReturn(['encryptedAes256', 'encryptedAes256fixed', 'custom']);
        $encryptorFactory->shouldReceive('getType')->with('encryptedAes256')->andReturn($aes256Type);
        $encryptorFactory->shouldReceive('getType')->with('encryptedAes256fixed')->andReturn($aes256FixedType);
        $encryptorFactory->shouldReceive('getType')->with('custom')->andReturn($customType);

        $databaseEncryptCommand = new DatabaseEncryptCommand(
            Mockery::mock(ManagerRegistry::class),
            $encryptorFactory,
            Mockery::mock(EntityService::class),
        );

        (new ReflectionMethod($databaseEncryptCommand, 'initialize'))->invoke(
            $databaseEncryptCommand,
            new ArrayInput(['--checkpoint' => $this->buildCheckpointPath(), '--manager' => 'secondary'], $databaseEncryptCommand->getDefinition()),
            new NullOutput(),
        );

        $checkpointService = $this->invoke($databaseEncryptCommand, 'getCheckpointService');

        static::assertInstanceOf(CheckpointService::class, $checkpointService);
        static::assertSame(
            ['command' => DatabaseEncryptCommand::NAME, 'manager' => 'secondary', 'saltVersion' => 'v2'],
            $checkpointService->getScope()->toArray(),
        );
    }

    public function testEveryRunReadsTheCheckpointAfresh(): void
    {
        $checkpointPath = $this->buildCheckpointPath();
        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $checkpointPath]);

        $firstRun = $this->invoke($databaseEncryptCommand, 'getCheckpointService');

        /* a command is a container service: the next run of the same instance must not resume the cursor the previous run left in memory */
        (new ReflectionMethod($databaseEncryptCommand, 'initialize'))->invoke(
            $databaseEncryptCommand,
            new ArrayInput(['--checkpoint' => $checkpointPath], $databaseEncryptCommand->getDefinition()),
            new NullOutput(),
        );

        static::assertNotSame($firstRun, $this->invoke($databaseEncryptCommand, 'getCheckpointService'));
    }

    public function testWithoutACheckpointTheRunStartsFromTheFirstRow(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);

        $databaseEncryptCommand = $this->buildCommand([]);

        static::assertNull($this->invoke($databaseEncryptCommand, 'getInitialIdentifierValues', $entityMetadataDto));
    }

    public function testTheCheckpointCarriesTheCursorIntoTheNextRun(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);
        $checkpointPath = $this->buildCheckpointPath();

        $writing = $this->buildCommand(['--checkpoint' => $checkpointPath]);
        $this->invoke($writing, 'onBatchProcessed', $entityMetadataDto, ['id' => 77]);

        $resuming = $this->buildCommand(['--checkpoint' => $checkpointPath]);

        static::assertSame(
            ['id' => 77],
            $this->invoke($resuming, 'getInitialIdentifierValues', $entityMetadataDto),
        );
    }

    public function testAFinishedRunLetsTheNextOneStartOver(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);
        $checkpointPath = $this->buildCheckpointPath();

        $finishing = $this->buildCommand(['--checkpoint' => $checkpointPath]);
        $this->invoke($finishing, 'onBatchProcessed', $entityMetadataDto, ['id' => 77]);
        $this->invoke($finishing, 'afterOperation', [$entityMetadataDto]);

        $resuming = $this->buildCommand(['--checkpoint' => $checkpointPath]);

        static::assertNull($this->invoke($resuming, 'getInitialIdentifierValues', $entityMetadataDto));
    }

    public function testDryRunWritesNoCheckpoint(): void
    {
        $entityMetadataDto = $this->buildEntityMetadataDto(stdClass::class);
        $checkpointPath = $this->buildCheckpointPath();

        $databaseEncryptCommand = $this->buildCommand(['--checkpoint' => $checkpointPath, '--dry-run' => true]);

        static::assertTrue($this->invoke($databaseEncryptCommand, 'isDryRun'));

        $this->invoke($databaseEncryptCommand, 'onBatchProcessed', $entityMetadataDto, ['id' => 77]);
        $this->invoke($databaseEncryptCommand, 'afterOperation', [$entityMetadataDto]);

        static::assertFileDoesNotExist($checkpointPath);
    }

    public function testDryRunLeavesEveryRowUntouched(): void
    {
        $entity = new stdClass();
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(1);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $firstEntityQuery = Mockery::mock(Query::class);
        $firstEntityQuery->shouldReceive('getResult')->once()->andReturn([$entity]);

        $firstEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $firstEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $firstEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($firstEntityQuery);

        $secondEntityQuery = Mockery::mock(Query::class);
        $secondEntityQuery->shouldReceive('getResult')->once()->andReturn([]);

        $secondEntityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $secondEntityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('setParameter')->with('lastId', 1)->andReturnSelf();
        $secondEntityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($secondEntityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $firstEntityQueryBuilder, $secondEntityQueryBuilder);

        $unitOfWork = Mockery::mock(UnitOfWork::class);
        $unitOfWork->shouldNotReceive('setOriginalEntityData');

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('clear')->once();
        $entityManager->shouldNotReceive('persist');
        $entityManager->shouldNotReceive('flush');

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')->once()->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand(
            $managerRegistry,
            Mockery::mock(EncryptorFactory::class),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute(['--dry-run' => true], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testTheProgressBarCountsOnlyTheRowsAfterTheCursor(): void
    {
        $className = stdClass::class;

        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('getTypeOfField')->with('id')->andReturn('integer');

        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);

        $countQuery = Mockery::mock(Query::class);
        $countQuery->shouldReceive('getSingleScalarResult')->once()->andReturn(0);

        $countQueryBuilder = Mockery::mock(QueryBuilder::class);
        $countQueryBuilder->shouldReceive('select')->with('COUNT(e)')->andReturnSelf();
        $countQueryBuilder->shouldReceive('andWhere')->once()->with('e.id > :lastId')->andReturnSelf();
        $countQueryBuilder->shouldReceive('setParameter')->once()->with('lastId', 42)->andReturnSelf();
        $countQueryBuilder->shouldReceive('getQuery')->once()->andReturn($countQuery);

        $entityQuery = Mockery::mock(Query::class);
        $entityQuery->shouldReceive('getResult')->once()->andReturn([]);

        $entityQueryBuilder = Mockery::mock(QueryBuilder::class);
        $entityQueryBuilder->shouldReceive('select')->with('e')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('addOrderBy')->with('e.id', 'ASC')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('setMaxResults')->with(50)->andReturnSelf();
        $entityQueryBuilder->shouldReceive('andWhere')->with('e.id > :lastId')->andReturnSelf();
        $entityQueryBuilder->shouldReceive('setParameter')->with('lastId', 42)->andReturnSelf();
        $entityQueryBuilder->shouldReceive('getQuery')->once()->andReturn($entityQuery);

        $entityRepository = Mockery::mock(EntityRepository::class);
        $entityRepository->shouldReceive('createQueryBuilder')
            ->with('e')
            ->andReturn($countQueryBuilder, $entityQueryBuilder);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn(Mockery::mock(UnitOfWork::class));

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')->once()->andReturn([$entityMetadataDto]);

        $databaseEncryptCommand = new DatabaseEncryptCommand(
            $managerRegistry,
            Mockery::mock(EncryptorFactory::class),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute(
            ['--entity' => $className, '--from-id' => '42'],
            ['interactive' => false],
        );

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    protected function tearDown(): void
    {
        foreach ($this->checkpointPaths as $checkpointPath) {
            if (true === \is_file($checkpointPath)) {
                \unlink($checkpointPath);
            }
        }

        $this->checkpointPaths = [];

        parent::tearDown();
    }

    /** @param array<string, mixed> $options */
    private function buildCommand(array $options, ?ManagerRegistry $managerRegistry = null): DatabaseEncryptCommand
    {
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldReceive('getTypeNames')->andReturn([]);

        $databaseEncryptCommand = new DatabaseEncryptCommand(
            $managerRegistry ?? Mockery::mock(ManagerRegistry::class),
            $encryptorFactory,
            Mockery::mock(EntityService::class),
        );

        /* the input, output and style a protected method reads are only wired once a run starts */
        (new ReflectionMethod($databaseEncryptCommand, 'initialize'))->invoke(
            $databaseEncryptCommand,
            new ArrayInput($options, $databaseEncryptCommand->getDefinition()),
            new NullOutput(),
        );

        return $databaseEncryptCommand;
    }

    /** @param string[] $identifierFieldNames */
    private function buildEntityMetadataDto(
        string $className,
        array $identifierFieldNames = ['id'],
        string $identifierType = 'integer',
    ): EntityMetadataDto {
        $classMetadata = Mockery::mock(ClassMetadata::class);
        $classMetadata->shouldReceive('getName')->andReturn($className);
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn($identifierFieldNames);
        $classMetadata->shouldReceive('getTypeOfField')->andReturn($identifierType);

        return new EntityMetadataDto($classMetadata, ['email' => 'encryptedAes256']);
    }

    /* the console style wraps a long message at the terminal width, which puts a line break inside the sentence under test */
    private function collapseWhitespace(string $display): string
    {
        return (string)\preg_replace('/\s+/', ' ', $display);
    }

    private function buildCheckpointScope(): CheckpointScopeDto
    {
        return new CheckpointScopeDto(DatabaseEncryptCommand::NAME, null, '');
    }

    private function buildCheckpointPath(): string
    {
        $path = \sys_get_temp_dir() . '/checkpoint-' . \bin2hex(\random_bytes(8)) . '.json';

        $this->checkpointPaths[] = $path;

        return $path;
    }

    private function invoke(DatabaseEncryptCommand $databaseEncryptCommand, string $methodName, mixed ...$arguments): mixed
    {
        return (new ReflectionMethod($databaseEncryptCommand, $methodName))->invoke($databaseEncryptCommand, ...$arguments);
    }
}
