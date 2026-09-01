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
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseRotateCommand;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
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

        (new CheckpointService($this->checkpointPath))->setIdentifierValues(
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

    private function assertCarriesTheCurrentPrefix(mixed $storedValue): void
    {
        static::assertIsString($storedValue);
        static::assertNotSame('', $this->currentPrefix, 'the current encryptors must be registered before asserting on their prefix');
        static::assertTrue(
            \str_starts_with($storedValue, $this->currentPrefix),
            'the stored value must carry the envelope prefix the current configuration writes',
        );
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
        $managerRegistry = new IntegrationManagerRegistry($entityManager);
        $encryptorFactory = new EncryptorFactory([
            new Aes256Encryptor(IntegrationDatabase::SALT_V1),
            new Aes256FixedEncryptor(IntegrationDatabase::SALT_V1),
            new FakeEncryptor(),
        ]);

        $commandTester = new CommandTester(
            new DatabaseRotateCommand($managerRegistry, $encryptorFactory, new EntityService($managerRegistry, $encryptorFactory)),
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
