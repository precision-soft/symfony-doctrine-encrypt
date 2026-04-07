<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Command;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Doctrine\ORM\UnitOfWork;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use Doctrine\Persistence\ObjectManager;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/** @internal */
final class AbstractDatabaseCommandTest extends TestCase
{
    use MockeryPHPUnitIntegration;

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

        $reflectionMethod = new \ReflectionMethod($databaseEncryptCommand, 'applyKeysetPagination');
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

        $reflectionMethod = new \ReflectionMethod($databaseEncryptCommand, 'applyKeysetPagination');
        $reflectionMethod->invoke(
            $databaseEncryptCommand,
            $queryBuilder,
            ['tenantId', 'userId'],
            ['tenantId' => 10, 'userId' => 20],
        );
    }

    public function testProcessEntitiesWithSingleEntityBatch(): void
    {
        $entity = new \stdClass();
        $className = \stdClass::class;

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

        $entityManager = Mockery::mock(ObjectManager::class);
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

    public function testProcessEntitiesExceptionResetsManager(): void
    {
        $entity = new \stdClass();
        $className = \stdClass::class;

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

        $entityManager = Mockery::mock(ObjectManager::class);
        $entityManager->shouldReceive('getRepository')->with($className)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('persist')->once()->with($entity);
        $entityManager->shouldReceive('flush')->once()->andThrow(new Exception('flush failed'));

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);
        $managerRegistry->shouldReceive('resetManager')->once()->with(null);

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

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }
}
