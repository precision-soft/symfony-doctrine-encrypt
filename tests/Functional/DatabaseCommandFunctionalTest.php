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
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseDecryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\BigintEncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IntegrationDatabase;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IntegrationManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\SkipIntegrationException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @internal
 */
#[Group('integration')]
final class DatabaseCommandFunctionalTest extends TestCase
{
    private ?EntityManagerInterface $entityManager = null;

    private string $checkpointPath = '';

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testEncryptCommandRewritesPlaintextRowsAsCiphertext(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $this->seedPlaintextRows($entityManager, 3);

        static::assertSame(Command::SUCCESS, $this->runCommand($entityManager, DatabaseEncryptCommand::class));

        foreach ($this->fetchRawColumn($entityManager) as $storedValue) {
            static::assertStringStartsWith(
                AbstractEncryptor::ENCRYPTION_MARKER . AbstractEncryptor::GLUE,
                $storedValue,
            );
        }

        $entityManager->clear();

        static::assertSame(
            ['plaintext-0', 'plaintext-1', 'plaintext-2'],
            $this->fetchThroughOrm($entityManager),
        );
    }

    /* "unchanged" differs per type and both are correct: the command re-reads plaintext and re-encrypts, so `Aes256Type` emits a fresh nonce while `Aes256FixedType` stays byte-stable */
    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testEncryptCommandIsIdempotent(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $this->seedPlaintextRows($entityManager, 3);

        $this->runCommand($entityManager, DatabaseEncryptCommand::class);
        $deterministicAfterFirstRun = $this->fetchRawColumn($entityManager, 'deterministicValue');

        $this->runCommand($entityManager, DatabaseEncryptCommand::class);

        static::assertSame(
            $deterministicAfterFirstRun,
            $this->fetchRawColumn($entityManager, 'deterministicValue'),
            'a deterministic ciphertext must survive a re-run byte for byte, or lookups stop matching',
        );

        foreach ($this->fetchThroughOrm($entityManager) as $index => $decrypted) {
            static::assertSame('plaintext-' . $index, $decrypted);
            static::assertStringStartsNotWith(AbstractEncryptor::ENCRYPTION_MARKER, $decrypted);
        }
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testDecryptCommandRestoresPlaintextOnDisk(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $this->seedPlaintextRows($entityManager, 3);

        $this->runCommand($entityManager, DatabaseEncryptCommand::class);

        static::assertSame(Command::SUCCESS, $this->runCommand($entityManager, DatabaseDecryptCommand::class));

        static::assertSame(
            ['plaintext-0', 'plaintext-1', 'plaintext-2'],
            $this->fetchRawColumn($entityManager),
        );
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testEncryptCommandCoversEveryRowAcrossBatches(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $this->seedPlaintextRows($entityManager, 7);

        static::assertSame(
            Command::SUCCESS,
            $this->runCommand($entityManager, DatabaseEncryptCommand::class, ['--batch-size' => '2']),
        );

        $storedValues = $this->fetchRawColumn($entityManager);

        static::assertCount(7, $storedValues);

        foreach ($storedValues as $storedValue) {
            static::assertStringStartsWith(
                AbstractEncryptor::ENCRYPTION_MARKER . AbstractEncryptor::GLUE,
                $storedValue,
            );
        }

        $entityManager->clear();

        static::assertCount(7, \array_unique($this->fetchThroughOrm($entityManager)));
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testInvalidBatchSizeFailsBeforeTouchingAnyRow(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $this->seedPlaintextRows($entityManager, 2);

        static::assertSame(
            Command::FAILURE,
            $this->runCommand($entityManager, DatabaseEncryptCommand::class, ['--batch-size' => '0']),
        );

        static::assertSame(['plaintext-0', 'plaintext-1'], $this->fetchRawColumn($entityManager));
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testFromIdOnABigintIdentifierSkipsTheRowsUpToIt(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        foreach (['first', 'second', 'third'] as $label) {
            $entityManager->getConnection()->insert('encrypted_bigint_subject', ['label' => $label, 'randomised' => $label . '-plaintext']);
        }

        $secondId = $entityManager->getConnection()->fetchOne('SELECT id FROM encrypted_bigint_subject WHERE label = ?', ['second']);

        static::assertSame(
            Command::SUCCESS,
            $this->runCommand($entityManager, DatabaseEncryptCommand::class, [
                '--entity' => BigintEncryptedSubject::class,
                '--from-id' => (string)$secondId,
                '--checkpoint' => $this->checkpointPath,
            ]),
        );

        /** @var list<string> $storedValues */
        $storedValues = $entityManager->getConnection()->fetchFirstColumn('SELECT randomised FROM encrypted_bigint_subject ORDER BY id ASC');

        static::assertSame(['first-plaintext', 'second-plaintext'], \array_slice($storedValues, 0, 2));
        static::assertStringStartsWith(AbstractEncryptor::ENCRYPTION_MARKER . AbstractEncryptor::GLUE, $storedValues[2]);

        /* the cursor the run wrote is the integer the engine handed back, never the string the option arrived as */
        $decoded = \json_decode((string)\file_get_contents($this->checkpointPath), true, 512, \JSON_THROW_ON_ERROR);

        static::assertIsArray($decoded);
        static::assertIsArray($decoded['entities']);
        static::assertIsArray($decoded['entities'][BigintEncryptedSubject::class]);
        static::assertIsInt($decoded['entities'][BigintEncryptedSubject::class]['id']);
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testEncryptAndDecryptHonourTheCheckpointAndTheDryRun(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);
        $this->seedPlaintextRows($entityManager, 4);

        static::assertSame(
            Command::SUCCESS,
            $this->runCommand($entityManager, DatabaseEncryptCommand::class, ['--batch-size' => '2', '--checkpoint' => $this->checkpointPath]),
        );

        $checkpointAfterEncrypt = (string)\file_get_contents($this->checkpointPath);
        $decoded = \json_decode($checkpointAfterEncrypt, true, 512, \JSON_THROW_ON_ERROR);

        static::assertIsArray($decoded);
        static::assertIsArray($decoded['completed']);
        static::assertContains(EncryptedSubject::class, $decoded['completed']);

        /* a decrypt cannot resume an encrypt's file, dry run or not */
        static::assertSame(
            Command::FAILURE,
            $this->runCommand($entityManager, DatabaseDecryptCommand::class, ['--checkpoint' => $this->checkpointPath, '--dry-run' => true]),
        );
        static::assertSame($checkpointAfterEncrypt, \file_get_contents($this->checkpointPath));

        $decryptCheckpointPath = $this->checkpointPath . '.decrypt';

        try {
            static::assertSame(
                Command::SUCCESS,
                $this->runCommand($entityManager, DatabaseDecryptCommand::class, ['--checkpoint' => $decryptCheckpointPath, '--dry-run' => true]),
            );
            static::assertFileDoesNotExist($decryptCheckpointPath);

            foreach ($this->fetchRawColumn($entityManager) as $storedValue) {
                static::assertStringStartsWith(AbstractEncryptor::ENCRYPTION_MARKER . AbstractEncryptor::GLUE, $storedValue);
            }

            static::assertSame(
                Command::SUCCESS,
                $this->runCommand($entityManager, DatabaseDecryptCommand::class, ['--batch-size' => '3', '--checkpoint' => $decryptCheckpointPath]),
            );
            static::assertFileExists($decryptCheckpointPath);
            static::assertSame(['plaintext-0', 'plaintext-1', 'plaintext-2', 'plaintext-3'], $this->fetchRawColumn($entityManager));
        } finally {
            if (true === \is_file($decryptCheckpointPath)) {
                \unlink($decryptCheckpointPath);
            }
        }
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->checkpointPath = \sys_get_temp_dir() . '/database-command-' . \bin2hex(\random_bytes(8)) . '.json';
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

    private function seedPlaintextRows(EntityManagerInterface $entityManager, int $count): void
    {
        for ($index = 0; $index < $count; ++$index) {
            $entityManager->getConnection()->insert(
                'encrypted_subject',
                [
                    'label' => 'row-' . $index,
                    'randomised' => 'plaintext-' . $index,
                    'deterministicValue' => 'plaintext-' . $index,
                ],
            );
        }
    }

    /**
     * @param class-string<AbstractDatabaseCommand> $commandClass
     * @param array<string, mixed> $options
     */
    private function runCommand(
        EntityManagerInterface $entityManager,
        string $commandClass,
        array $options = [],
    ): int {
        $managerRegistry = new IntegrationManagerRegistry($entityManager);
        $encryptorFactory = new EncryptorFactory([
            new Aes256Encryptor(IntegrationDatabase::SALT_V1),
            new Aes256FixedEncryptor(IntegrationDatabase::SALT_V1),
            new FakeEncryptor(),
        ]);

        $command = new $commandClass(
            $managerRegistry,
            $encryptorFactory,
            new EntityService($managerRegistry, $encryptorFactory),
        );

        $commandTester = new CommandTester($command);
        $commandTester->execute($options, ['interactive' => false]);

        return $commandTester->getStatusCode();
    }

    /** @return list<string> */
    private function fetchRawColumn(EntityManagerInterface $entityManager, string $column = 'randomised'): array
    {
        /** @var list<string> $values */
        $values = $entityManager->getConnection()->fetchFirstColumn(
            \sprintf('SELECT %s FROM encrypted_subject ORDER BY id ASC', $column),
        );

        return $values;
    }

    /** @return list<string> */
    private function fetchThroughOrm(EntityManagerInterface $entityManager): array
    {
        $values = [];

        foreach ($this->fetchRawColumn($entityManager) as $storedValue) {
            $values[] = (new Aes256Encryptor(IntegrationDatabase::SALT_V1))->decrypt($storedValue);
        }

        return $values;
    }
}
