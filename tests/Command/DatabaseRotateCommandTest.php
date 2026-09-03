<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Mapping\DiscriminatorColumnMapping;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Doctrine\ORM\UnitOfWork;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use Mockery\MockInterface;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseRotateCommand;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedChild;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedParent;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;
use ReflectionMethod;
use stdClass;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;

/** @internal */
final class DatabaseRotateCommandTest extends AbstractTestCase
{
    /* an underscore is legal in a salt version and is also the LIKE single character wildcard */
    private const SALT_VERSION = 'v_2';
    private const SALT = 'rotate-command-test-salt-value-v2';

    private BufferedOutput $output;

    public static function getMockDto(): MockDto
    {
        return new MockDto(
            EntityService::class,
            [
                new MockDto(ManagerRegistry::class),
                new MockDto(EncryptorFactory::class),
            ],
        );
    }

    public function testCommandName(): void
    {
        static::assertSame(DatabaseRotateCommand::NAME, 'precision-soft:doctrine:database:rotate');
    }

    public function testExecuteWithNoEntitiesReturnsSuccess(): void
    {
        $entityService = $this->get(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([]);

        $databaseRotateCommand = new DatabaseRotateCommand(
            $this->get(ManagerRegistry::class),
            $this->get(EncryptorFactory::class),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseRotateCommand);

        $commandTester = new CommandTester($databaseRotateCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('no entities found to encrypt', $commandTester->getDisplay());
        static::assertStringNotContainsString('encryption finished', $commandTester->getDisplay());
    }

    public function testExecuteWithExceptionReturnsFailure(): void
    {
        $entityService = $this->get(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andThrow(new Exception('database error'));

        $databaseRotateCommand = new DatabaseRotateCommand(
            $this->get(ManagerRegistry::class),
            $this->get(EncryptorFactory::class),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseRotateCommand);

        $commandTester = new CommandTester($databaseRotateCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }

    public function testTheVerifyOptionIsDeclared(): void
    {
        $databaseRotateCommand = $this->buildCommand(Mockery::mock(ManagerRegistry::class), Mockery::mock(EncryptorFactory::class));

        static::assertTrue($databaseRotateCommand->getDefinition()->hasOption('verify'));
        static::assertFalse($databaseRotateCommand->getDefinition()->getOption('verify')->acceptValue());
    }

    public function testRotateRewritesThroughTheRealEncryptor(): void
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

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')->once()->andReturn([$entityMetadataDto]);

        /* rotation must never swap in the fake encryptor: the flush is exactly where the current salt has to be applied */
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldNotReceive('getType');
        $encryptorFactory->shouldNotReceive('getEncryptor');

        $databaseRotateCommand = new DatabaseRotateCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseRotateCommand);

        $commandTester = new CommandTester($databaseRotateCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('[ENCRYPT]', $commandTester->getDisplay());
    }

    public function testDryRunWithVerifyReportsTheStaleRowsWithoutTouchingThem(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')->once()->andReturn(3);

        $commandTester = $this->runRotate(['--dry-run' => true, '--verify' => true], $connection);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString(
            'rotation verification failed for stdClass::randomised (3 rows)',
            (string)\preg_replace('/\s+/', ' ', $commandTester->getDisplay()),
        );
    }

    public function testDryRunWithVerifyPassesWhenEveryRowCarriesTheCurrentSalt(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')->once()->andReturn(0);

        $commandTester = $this->runRotate(['--dry-run' => true, '--verify' => true], $connection);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());
    }

    public function testVerifyScopesTheCountToTheDiscriminatorUnderSingleTableInheritance(): void
    {
        $capturedSql = null;
        $capturedParameters = null;

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')
            ->once()
            ->andReturnUsing(static function (string $sql, array $parameters) use (&$capturedSql, &$capturedParameters): int {
                $capturedSql = $sql;
                $capturedParameters = $parameters;

                return 0;
            });

        $databaseRotateCommand = $this->buildCommand(
            $this->buildManagerRegistry($connection),
            $this->buildEncryptorFactory(new Aes256Encryptor([self::SALT_VERSION => self::SALT], self::SALT_VERSION)),
        );

        (new ReflectionMethod($databaseRotateCommand, 'verifyCurrentSalt'))->invoke(
            $databaseRotateCommand,
            [$this->buildEntityMetadataDto(true)],
        );

        static::assertSame(
            "SELECT COUNT(*) FROM `encrypted_subject` WHERE `randomised` IS NOT NULL AND `randomised` NOT LIKE ? ESCAPE '!' AND `kind` IN (?, ?, ?)",
            $capturedSql,
        );
        static::assertSame(["<ENC>\0v1\0v!_2\0%", 'parent', 'child', '7'], $capturedParameters);
    }

    public function testVerifyAddsNoDiscriminatorTermOutsideSingleTableInheritance(): void
    {
        $capturedSql = null;
        $capturedParameters = null;

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')
            ->once()
            ->andReturnUsing(static function (string $sql, array $parameters) use (&$capturedSql, &$capturedParameters): int {
                $capturedSql = $sql;
                $capturedParameters = $parameters;

                return 0;
            });

        $databaseRotateCommand = $this->buildCommand(
            $this->buildManagerRegistry($connection),
            $this->buildEncryptorFactory(new Aes256Encryptor([self::SALT_VERSION => self::SALT], self::SALT_VERSION)),
        );

        /* a JOINED hierarchy carries a discriminator column too, but every class has its own table */
        $classMetadata = $this->buildClassMetadata();
        $classMetadata->discriminatorColumn = new DiscriminatorColumnMapping('string', 'kind', 'kind');
        $classMetadata->discriminatorMap = ['parent' => stdClass::class, 'child' => EncryptedChild::class];
        $classMetadata->subClasses = [EncryptedChild::class];

        (new ReflectionMethod($databaseRotateCommand, 'verifyCurrentSalt'))->invoke(
            $databaseRotateCommand,
            [new EntityMetadataDto($classMetadata, ['randomised' => 'encryptedAes256'])],
        );

        static::assertSame(
            "SELECT COUNT(*) FROM `encrypted_subject` WHERE `randomised` IS NOT NULL AND `randomised` NOT LIKE ? ESCAPE '!'",
            $capturedSql,
        );
        static::assertSame(["<ENC>\0v1\0v!_2\0%"], $capturedParameters);
    }

    public function testEscapeLikePatternNeutralisesEveryWildcard(): void
    {
        $databaseRotateCommand = $this->buildCommand(Mockery::mock(ManagerRegistry::class), Mockery::mock(EncryptorFactory::class));

        static::assertSame(
            '!!a!_b!%c',
            (new ReflectionMethod($databaseRotateCommand, 'escapeLikePattern'))->invoke($databaseRotateCommand, '!a_b%c'),
        );
    }

    public function testVerifyMatchesTheSaltVersionLiterallyWhenItCarriesAnUnderscore(): void
    {
        $capturedSql = null;
        $capturedParameters = null;

        $encryptor = new Aes256Encryptor([self::SALT_VERSION => self::SALT], self::SALT_VERSION);

        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')
            ->once()
            ->andReturnUsing(static function (string $sql, array $parameters) use (&$capturedSql, &$capturedParameters): int {
                $capturedSql = $sql;
                $capturedParameters = $parameters;

                return 0;
            });

        $databaseRotateCommand = $this->buildCommand(
            $this->buildManagerRegistry($connection),
            $this->buildEncryptorFactory($encryptor),
        );

        (new ReflectionMethod($databaseRotateCommand, 'verifyCurrentSalt'))->invoke(
            $databaseRotateCommand,
            [$this->buildEntityMetadataDto()],
        );

        static::assertIsString($capturedSql);
        static::assertStringContainsString("NOT LIKE ? ESCAPE '!'", $capturedSql);
        static::assertSame(["<ENC>\0v1\0v!_2\0%"], $capturedParameters);
        static::assertStringContainsString('rotation verification passed', $this->output->fetch());
    }

    public function testVerifyFailsWhenRowsAreStillOnAnotherSalt(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')->once()->andReturn(3);

        $databaseRotateCommand = $this->buildCommand(
            $this->buildManagerRegistry($connection),
            $this->buildEncryptorFactory(new Aes256Encryptor([self::SALT_VERSION => self::SALT], self::SALT_VERSION)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('rotation verification failed for stdClass::randomised (3 rows)');

        (new ReflectionMethod($databaseRotateCommand, 'verifyCurrentSalt'))->invoke(
            $databaseRotateCommand,
            [$this->buildEntityMetadataDto()],
        );
    }

    public function testVerifyRejectsANonNumericCount(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('fetchOne')->once()->andReturn('not a count');

        $databaseRotateCommand = $this->buildCommand(
            $this->buildManagerRegistry($connection),
            $this->buildEncryptorFactory(new Aes256Encryptor([self::SALT_VERSION => self::SALT], self::SALT_VERSION)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('verification count query returned non-numeric result');

        (new ReflectionMethod($databaseRotateCommand, 'verifyCurrentSalt'))->invoke(
            $databaseRotateCommand,
            [$this->buildEntityMetadataDto()],
        );
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->output = new BufferedOutput();
    }

    private function buildCommand(ManagerRegistry $managerRegistry, EncryptorFactory $encryptorFactory): DatabaseRotateCommand
    {
        $databaseRotateCommand = new DatabaseRotateCommand($managerRegistry, $encryptorFactory, Mockery::mock(EntityService::class));

        /* the input, output and style a protected method reads are only wired once a run starts */
        (new ReflectionMethod($databaseRotateCommand, 'initialize'))->invoke(
            $databaseRotateCommand,
            new ArrayInput([], $databaseRotateCommand->getDefinition()),
            $this->output,
        );

        return $databaseRotateCommand;
    }

    /** @param Connection&MockInterface $connection */
    private function buildManagerRegistry(Connection $connection): ManagerRegistry
    {
        $platform = Mockery::mock(AbstractPlatform::class);
        $platform->shouldReceive('quoteIdentifier')->andReturnUsing(static fn(string $identifier): string => '`' . $identifier . '`');
        $platform->shouldReceive('quoteStringLiteral')->andReturnUsing(static fn(string $value): string => "'" . $value . "'");

        $connection->shouldReceive('getDatabasePlatform')->andReturn($platform);

        $entityManager = Mockery::mock(EntityManagerInterface::class);
        $entityManager->shouldReceive('getConnection')->andReturn($connection);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        return $managerRegistry;
    }

    private function buildEncryptorFactory(Aes256Encryptor $aes256Encryptor): EncryptorFactory
    {
        $aes256Type = Mockery::mock(Aes256Type::class);
        $aes256Type->shouldReceive('getEncryptor')->andReturn($aes256Encryptor);

        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $encryptorFactory->shouldReceive('getType')->with('encryptedAes256')->andReturn($aes256Type);

        return $encryptorFactory;
    }

    /** @phpstan-return OrmClassMetadata<object>&MockInterface */
    private function buildClassMetadata(bool $singleTable = false): OrmClassMetadata
    {
        $classMetadata = Mockery::mock(OrmClassMetadata::class);
        $classMetadata->name = stdClass::class;
        $classMetadata->shouldReceive('getName')->andReturn(stdClass::class);
        $classMetadata->shouldReceive('getTableName')->andReturn('encrypted_subject');
        $classMetadata->shouldReceive('getColumnName')->with('randomised')->andReturn('randomised');
        $classMetadata->shouldReceive('getIdentifierFieldNames')->andReturn(['id']);
        $classMetadata->shouldReceive('isInheritanceTypeSingleTable')->andReturn($singleTable);

        /* two subclasses and an integer discriminator value: the term must list every class the walk loads, as strings */
        if (true === $singleTable) {
            $classMetadata->discriminatorColumn = new DiscriminatorColumnMapping('string', 'kind', 'kind');
            $classMetadata->discriminatorMap = ['parent' => stdClass::class, 'child' => EncryptedChild::class, 7 => EncryptedParent::class, 'other' => EncryptedSubject::class];
            $classMetadata->subClasses = [EncryptedChild::class, EncryptedParent::class];
        }

        return $classMetadata;
    }

    private function buildEntityMetadataDto(bool $singleTable = false): EntityMetadataDto
    {
        return new EntityMetadataDto($this->buildClassMetadata($singleTable), ['randomised' => 'encryptedAes256']);
    }

    /**
     * @param array<string, mixed> $input
     * @param Connection&MockInterface $connection
     */
    private function runRotate(array $input, Connection $connection): CommandTester
    {
        $entity = new stdClass();
        $classMetadata = $this->buildClassMetadata();
        $classMetadata->shouldReceive('getIdentifierValues')->with($entity)->andReturn(['id' => 1]);
        $entityMetadataDto = new EntityMetadataDto($classMetadata, ['randomised' => 'encryptedAes256']);

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
        $entityManager->shouldReceive('getRepository')->with(stdClass::class)->andReturn($entityRepository);
        $entityManager->shouldReceive('getUnitOfWork')->andReturn($unitOfWork);
        $entityManager->shouldReceive('getConnection')->andReturn($connection);
        $entityManager->shouldReceive('clear')->once();
        $entityManager->shouldNotReceive('persist');
        $entityManager->shouldNotReceive('flush');

        $platform = Mockery::mock(AbstractPlatform::class);
        $platform->shouldReceive('quoteIdentifier')->andReturnUsing(static fn(string $identifier): string => '`' . $identifier . '`');
        $platform->shouldReceive('quoteStringLiteral')->andReturnUsing(static fn(string $value): string => "'" . $value . "'");
        $connection->shouldReceive('getDatabasePlatform')->andReturn($platform);

        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $managerRegistry->shouldReceive('getManager')->with(null)->andReturn($entityManager);

        $entityService = Mockery::mock(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')->once()->andReturn([$entityMetadataDto]);

        $databaseRotateCommand = new DatabaseRotateCommand(
            $managerRegistry,
            $this->buildEncryptorFactory(new Aes256Encryptor([self::SALT_VERSION => self::SALT], self::SALT_VERSION)),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseRotateCommand);

        $commandTester = new CommandTester($databaseRotateCommand);
        $commandTester->execute($input, ['interactive' => false]);

        return $commandTester;
    }
}
