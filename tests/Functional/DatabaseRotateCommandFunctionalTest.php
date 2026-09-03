<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Functional;

use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Command\AbstractDatabaseCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseRotateCommand;
use PrecisionSoft\Doctrine\Encrypt\Dto\CheckpointScopeDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedChild;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedParent;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\FailingEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IntegrationDatabase;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IntegrationManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\LegacyCiphertext;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\SkipIntegrationException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/** @internal */
#[Group('integration')]
final class DatabaseRotateCommandFunctionalTest extends TestCase
{
    private const CURRENT_SALT_VERSION = 'v2';
    private const LEGACY_SALT_VERSION = 'v1';

    private ?EntityManagerInterface $entityManager = null;

    private string $checkpointPath = '';

    private string $currentPrefix = '';

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testRotateRewritesOldSaltDirectlyToCurrentSalt(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);
        $legacyFixedEncryptor = new Aes256FixedEncryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $this->insertRow($entityManager, 'old-row', [
            'randomised' => $legacyRandomEncryptor->encrypt('secret-value'),
            'deterministicValue' => $legacyFixedEncryptor->encrypt('lookup-value'),
        ]);

        [$currentRandomEncryptor, $currentFixedEncryptor] = $this->registerCurrentEncryptors();

        $commandTester = $this->runRotate($entityManager, [
            '--batch-size' => '1',
            '--entity' => EncryptedSubject::class,
            '--checkpoint' => $this->checkpointPath,
            '--verify' => true,
        ]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());
        static::assertContains(EncryptedSubject::class, $this->readCheckpointKey('completed'));

        $row = $this->fetchRow($entityManager, 'old-row');

        foreach (['randomised' => 'secret-value', 'deterministicValue' => 'lookup-value'] as $column => $plaintext) {
            $storedValue = $row[$column];

            $this->assertCarriesTheCurrentPrefix($storedValue);
            static::assertNotSame($plaintext, $storedValue);
        }

        static::assertIsString($row['randomised']);
        static::assertIsString($row['deterministicValue']);
        static::assertSame('secret-value', $currentRandomEncryptor->decrypt($row['randomised']));
        static::assertSame('lookup-value', $currentFixedEncryptor->decrypt($row['deterministicValue']));
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testRotateUpgradesALegacyEnvelopeToTheCurrentSalt(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        $this->insertRow($entityManager, 'legacy-row', [
            'randomised' => LegacyCiphertext::produce(IntegrationDatabase::SALT_V1, 'legacy-secret'),
        ]);

        [$currentRandomEncryptor] = $this->registerCurrentEncryptors();

        $commandTester = $this->runRotate($entityManager, ['--entity' => EncryptedSubject::class, '--verify' => true]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());

        $storedValue = $this->fetchRow($entityManager, 'legacy-row')['randomised'];

        static::assertIsString($storedValue);
        static::assertCount(6, \explode(AbstractEncryptor::GLUE, $storedValue));
        $this->assertCarriesTheCurrentPrefix($storedValue);
        static::assertSame('legacy-secret', $currentRandomEncryptor->decrypt($storedValue));
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testDryRunLeavesEveryStoredValueAndTheCheckpointUntouched(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $this->insertRow($entityManager, 'old-row', ['randomised' => $legacyRandomEncryptor->encrypt('secret-value')]);

        $this->registerCurrentEncryptors();

        $before = $this->fetchRow($entityManager, 'old-row')['randomised'];

        $commandTester = $this->runRotate($entityManager, [
            '--entity' => EncryptedSubject::class,
            '--checkpoint' => $this->checkpointPath,
            '--dry-run' => true,
        ]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertFileDoesNotExist($this->checkpointPath);
        static::assertSame($before, $this->fetchRow($entityManager, 'old-row')['randomised']);
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testVerifyFailsWhenARowIsLeftOnTheOldSalt(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $this->insertRow($entityManager, 'first-row', ['randomised' => $legacyRandomEncryptor->encrypt('first-secret')]);
        $this->insertRow($entityManager, 'second-row', ['randomised' => $legacyRandomEncryptor->encrypt('second-secret')]);

        $this->registerCurrentEncryptors();

        /* the cursor sends the run past the first row, so it stays on the old salt and verification has to catch it */
        $commandTester = $this->runRotate($entityManager, [
            '--entity' => EncryptedSubject::class,
            '--from-id' => (string)$this->fetchRow($entityManager, 'first-row')['id'],
            '--verify' => true,
        ]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString('rotation verification failed', $commandTester->getDisplay());
        $this->assertCarriesTheCurrentPrefix($this->fetchRow($entityManager, 'second-row')['randomised']);
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testAStoredCursorResumesTheRunAndACompletedRunStartsOver(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $this->insertRow($entityManager, 'first-row', ['randomised' => $legacyRandomEncryptor->encrypt('first-secret')]);
        $this->insertRow($entityManager, 'second-row', ['randomised' => $legacyRandomEncryptor->encrypt('second-secret')]);

        $this->registerCurrentEncryptors();

        $firstRowBefore = $this->fetchRow($entityManager, 'first-row')['randomised'];

        (new CheckpointService($this->buildCheckpointScope(), $this->checkpointPath))->setIdentifierValues(
            EncryptedSubject::class,
            ['id' => $this->fetchRow($entityManager, 'first-row')['id']],
        );

        $commandTester = $this->runRotate($entityManager, [
            '--entity' => EncryptedSubject::class,
            '--checkpoint' => $this->checkpointPath,
        ]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertSame($firstRowBefore, $this->fetchRow($entityManager, 'first-row')['randomised']);
        $this->assertCarriesTheCurrentPrefix($this->fetchRow($entityManager, 'second-row')['randomised']);

        /* the first run marked the class completed, so this one must drop the stale cursor and pick the skipped row up */
        $commandTester = $this->runRotate($entityManager, [
            '--entity' => EncryptedSubject::class,
            '--checkpoint' => $this->checkpointPath,
            '--verify' => true,
        ]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        $this->assertCarriesTheCurrentPrefix($this->fetchRow($entityManager, 'first-row')['randomised']);
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testDryRunWithVerifyIsACheckOfTheStoredSalts(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $this->insertRow($entityManager, 'first-row', ['randomised' => $legacyRandomEncryptor->encrypt('first-secret')]);
        $this->insertRow($entityManager, 'second-row', ['randomised' => $legacyRandomEncryptor->encrypt('second-secret')]);

        $this->registerCurrentEncryptors();

        $before = [$this->fetchRow($entityManager, 'first-row')['randomised'], $this->fetchRow($entityManager, 'second-row')['randomised']];

        $commandTester = $this->runRotate($entityManager, ['--entity' => EncryptedSubject::class, '--dry-run' => true, '--verify' => true]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        /* the console style wraps the long class name mid-word, so the sentence is asserted in two pieces */
        static::assertStringContainsString('rotation verification failed for', $commandTester->getDisplay());
        static::assertStringContainsString('(2 rows)', $commandTester->getDisplay());
        static::assertSame($before, [$this->fetchRow($entityManager, 'first-row')['randomised'], $this->fetchRow($entityManager, 'second-row')['randomised']]);

        static::assertSame(Command::SUCCESS, $this->runRotate($entityManager, ['--entity' => EncryptedSubject::class])->getStatusCode());

        $commandTester = $this->runRotate($entityManager, ['--entity' => EncryptedSubject::class, '--dry-run' => true, '--verify' => true]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testVerifyCountsOnlyTheRowsOfTheSelectedClassUnderSingleTableInheritance(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $connection = $entityManager->getConnection();
        $connection->insert('encrypted_kin', ['kind' => 'parent', 'label' => 'parent-row', 'secret' => $legacyRandomEncryptor->encrypt('parent-secret')]);
        $connection->insert('encrypted_kin', ['kind' => 'child', 'label' => 'child-row', 'secret' => $legacyRandomEncryptor->encrypt('child-secret')]);

        $this->registerCurrentEncryptors();

        /* the child walk never loads the parent row, so a parent row left on the old salt is not the child's failure */
        $commandTester = $this->runRotate($entityManager, ['--entity' => EncryptedChild::class, '--verify' => true]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());
        $this->assertCarriesTheCurrentPrefix($this->fetchKinSecret($entityManager, 'child-row'));
        $this->assertDoesNotCarryTheCurrentPrefix($this->fetchKinSecret($entityManager, 'parent-row'));

        /* the parent walk is polymorphic, so its verification covers the whole hierarchy */
        $commandTester = $this->runRotate($entityManager, ['--entity' => EncryptedParent::class, '--verify' => true]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        $this->assertCarriesTheCurrentPrefix($this->fetchKinSecret($entityManager, 'parent-row'));
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testACheckpointOfAnotherCommandIsRefused(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        $this->insertRow($entityManager, 'old-row', ['randomised' => $legacyRandomEncryptor->encrypt('secret-value')]);

        $this->registerCurrentEncryptors();

        static::assertSame(
            Command::SUCCESS,
            $this->runRotate($entityManager, ['--entity' => EncryptedSubject::class, '--checkpoint' => $this->checkpointPath])->getStatusCode(),
        );

        $commandTester = $this->runCommand($entityManager, DatabaseEncryptCommand::class, ['--entity' => EncryptedSubject::class, '--checkpoint' => $this->checkpointPath]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString(
            'was written by `' . DatabaseRotateCommand::NAME . '`, not by `' . DatabaseEncryptCommand::NAME . '`',
            (string)\preg_replace('/\s+/', ' ', $commandTester->getDisplay()),
        );
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testAFailedBatchLeavesTheCursorOnTheLastCommittedRowAndTheRerunFinishes(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $legacyRandomEncryptor = new Aes256Encryptor([self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1], self::LEGACY_SALT_VERSION);

        foreach (['first', 'second', 'third', 'fourth', 'fifth'] as $label) {
            $this->insertRow($entityManager, $label . '-row', ['randomised' => $legacyRandomEncryptor->encrypt($label . '-secret')]);
        }

        $saltsByVersion = [self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1, self::CURRENT_SALT_VERSION => IntegrationDatabase::SALT_V2];
        $failingEncryptor = (new FailingEncryptor($saltsByVersion, self::CURRENT_SALT_VERSION, self::LEGACY_SALT_VERSION))->failAfter(2);

        IntegrationDatabase::registerTypes($failingEncryptor, new Aes256FixedEncryptor($saltsByVersion, self::CURRENT_SALT_VERSION, self::LEGACY_SALT_VERSION));
        $this->currentPrefix = $failingEncryptor->getCurrentEnvelopePrefix();

        $commandTester = $this->runRotate($entityManager, [
            '--entity' => EncryptedSubject::class,
            '--batch-size' => '2',
            '--checkpoint' => $this->checkpointPath,
        ]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        static::assertStringContainsString('the encryptor gave up mid-batch', $commandTester->getDisplay());

        $this->assertCarriesTheCurrentPrefix($this->fetchRow($entityManager, 'first-row')['randomised']);
        $this->assertCarriesTheCurrentPrefix($this->fetchRow($entityManager, 'second-row')['randomised']);

        foreach (['third', 'fourth', 'fifth'] as $label) {
            $this->assertDoesNotCarryTheCurrentPrefix($this->fetchRow($entityManager, $label . '-row')['randomised']);
        }

        static::assertSame(
            [EncryptedSubject::class => ['id' => $this->fetchRow($entityManager, 'second-row')['id']]],
            $this->readCheckpointKey('entities'),
        );

        /* the failed flush closed the manager, as it would in a real process; the rerun is a new process with the same file */
        $rerunEntityManager = IntegrationDatabase::createEntityManager($entityManager->getConnection());
        $this->entityManager = $rerunEntityManager;
        $this->registerCurrentEncryptors();

        $commandTester = $this->runRotate($rerunEntityManager, [
            '--entity' => EncryptedSubject::class,
            '--batch-size' => '2',
            '--checkpoint' => $this->checkpointPath,
            '--verify' => true,
        ]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());
        static::assertContains(EncryptedSubject::class, $this->readCheckpointKey('completed'));

        foreach (['first', 'second', 'third', 'fourth', 'fifth'] as $label) {
            $this->assertCarriesTheCurrentPrefix($this->fetchRow($rerunEntityManager, $label . '-row')['randomised']);
        }
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->checkpointPath = \sys_get_temp_dir() . '/rotation-' . \bin2hex(\random_bytes(8)) . '.json';
    }

    protected function tearDown(): void
    {
        if (true === \is_file($this->checkpointPath)) {
            \unlink($this->checkpointPath);
        }

        if (null !== $this->entityManager) {
            IntegrationDatabase::dropSchema($this->entityManager);
            $this->entityManager->getConnection()->close();
            $this->entityManager = null;
        }

        parent::tearDown();
    }

    private function fetchKinSecret(EntityManagerInterface $entityManager, string $label): mixed
    {
        return $entityManager->getConnection()->fetchOne('SELECT secret FROM encrypted_kin WHERE label = ?', [$label]);
    }

    private function assertDoesNotCarryTheCurrentPrefix(mixed $storedValue): void
    {
        static::assertIsString($storedValue);
        static::assertNotSame('', $this->currentPrefix, 'the current encryptors must be registered before asserting on their prefix');
        static::assertFalse(
            \str_starts_with($storedValue, $this->currentPrefix),
            'the stored value must still carry the envelope prefix of the previous configuration',
        );
    }

    private function assertCarriesTheCurrentPrefix(mixed $storedValue): void
    {
        static::assertIsString($storedValue);
        static::assertNotSame('', $this->currentPrefix, 'the current encryptors must be registered before asserting on their prefix');
        static::assertTrue(
            \str_starts_with($storedValue, $this->currentPrefix),
            'the stored value must carry the envelope prefix the current configuration writes',
        );
    }

    private function buildCheckpointScope(): CheckpointScopeDto
    {
        return new CheckpointScopeDto(DatabaseRotateCommand::NAME, null, self::CURRENT_SALT_VERSION);
    }

    /** @return array{Aes256Encryptor, Aes256FixedEncryptor} */
    private function registerCurrentEncryptors(): array
    {
        $saltsByVersion = [
            self::LEGACY_SALT_VERSION => IntegrationDatabase::SALT_V1,
            self::CURRENT_SALT_VERSION => IntegrationDatabase::SALT_V2,
        ];

        $randomEncryptor = new Aes256Encryptor($saltsByVersion, self::CURRENT_SALT_VERSION, self::LEGACY_SALT_VERSION);
        $fixedEncryptor = new Aes256FixedEncryptor($saltsByVersion, self::CURRENT_SALT_VERSION, self::LEGACY_SALT_VERSION);

        IntegrationDatabase::registerTypes($randomEncryptor, $fixedEncryptor);

        $this->currentPrefix = $randomEncryptor->getCurrentEnvelopePrefix();

        return [$randomEncryptor, $fixedEncryptor];
    }

    /**
     * @param array<string, string> $encryptedColumns
     */
    private function insertRow(EntityManagerInterface $entityManager, string $label, array $encryptedColumns): void
    {
        $entityManager->getConnection()->insert('encrypted_subject', ['label' => $label] + $encryptedColumns);
    }

    /** @return array<string, mixed> */
    private function fetchRow(EntityManagerInterface $entityManager, string $label): array
    {
        $row = $entityManager->getConnection()->fetchAssociative(
            'SELECT id, randomised, deterministicValue FROM encrypted_subject WHERE label = ?',
            [$label],
        );

        static::assertIsArray($row);

        return $row;
    }

    /** @param array<string, mixed> $input */
    private function runRotate(EntityManagerInterface $entityManager, array $input): CommandTester
    {
        return $this->runCommand($entityManager, DatabaseRotateCommand::class, $input);
    }

    /**
     * @param class-string<AbstractDatabaseCommand> $commandClass
     * @param array<string, mixed> $input
     */
    private function runCommand(EntityManagerInterface $entityManager, string $commandClass, array $input): CommandTester
    {
        $managerRegistry = new IntegrationManagerRegistry($entityManager);
        $encryptorFactory = new EncryptorFactory([
            new Aes256Encryptor(IntegrationDatabase::SALT_V1),
            new Aes256FixedEncryptor(IntegrationDatabase::SALT_V1),
            new FakeEncryptor(),
        ]);

        $commandTester = new CommandTester(
            new $commandClass($managerRegistry, $encryptorFactory, new EntityService($managerRegistry, $encryptorFactory)),
        );

        $commandTester->execute($input, ['interactive' => false]);

        return $commandTester;
    }

    /** @return mixed[] */
    private function readCheckpointKey(string $key): array
    {
        $decoded = \json_decode((string)\file_get_contents($this->checkpointPath), true, 512, \JSON_THROW_ON_ERROR);

        static::assertIsArray($decoded);
        static::assertArrayHasKey($key, $decoded);
        static::assertIsArray($decoded[$key]);

        return $decoded[$key];
    }

    private function boot(string $environmentVariable): EntityManagerInterface
    {
        try {
            $connection = IntegrationDatabase::createConnection($environmentVariable);
        } catch (SkipIntegrationException $skipIntegrationException) {
            static::markTestSkipped($skipIntegrationException->getMessage());
        }

        IntegrationDatabase::registerTypes(
            new Aes256Encryptor(IntegrationDatabase::SALT_V1),
            new Aes256FixedEncryptor(IntegrationDatabase::SALT_V1),
        );

        $this->entityManager = IntegrationDatabase::createEntityManager($connection);
        IntegrationDatabase::createSchema($this->entityManager);

        return $this->entityManager;
    }
}
