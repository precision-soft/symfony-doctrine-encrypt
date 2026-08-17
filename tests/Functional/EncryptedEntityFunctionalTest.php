<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Functional;

use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IntegrationDatabase;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\IntegrationManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\SkipIntegrationException;
use Throwable;

/**
 * @internal
 */
#[Group('integration')]
final class EncryptedEntityFunctionalTest extends TestCase
{
    private ?EntityManagerInterface $entityManager = null;

    protected function tearDown(): void
    {
        if (null !== $this->entityManager) {
            IntegrationDatabase::dropSchema($this->entityManager);
            $this->entityManager->getConnection()->close();
            $this->entityManager = null;
        }

        parent::tearDown();
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testEncryptedFieldIsCiphertextOnDiskAndPlaintextInPhp(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        $encryptedSubject = (new EncryptedSubject())
            ->setLabel('round-trip')
            ->setRandomised('the randomised secret')
            ->setDeterministicValue('the deterministic secret');

        $entityManager->persist($encryptedSubject);
        $entityManager->flush();

        $identifier = $encryptedSubject->getId();
        static::assertNotNull($identifier);

        $entityManager->clear();

        $reloaded = $entityManager->find(EncryptedSubject::class, $identifier);
        static::assertInstanceOf(EncryptedSubject::class, $reloaded);
        static::assertSame('the randomised secret', $reloaded->getRandomised());
        static::assertSame('the deterministic secret', $reloaded->getDeterministicValue());

        $storedRow = $this->fetchRawRow($entityManager->getConnection(), $identifier);

        foreach (['randomised', 'deterministicValue'] as $column) {
            static::assertIsString($storedRow[$column]);
            static::assertStringStartsWith(
                AbstractEncryptor::ENCRYPTION_MARKER . AbstractEncryptor::GLUE,
                $storedRow[$column],
            );
            static::assertStringNotContainsString('secret', $storedRow[$column]);
        }
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testNullEncryptedFieldStaysNull(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        $encryptedSubject = (new EncryptedSubject())->setLabel('nulls');

        $entityManager->persist($encryptedSubject);
        $entityManager->flush();

        $identifier = $encryptedSubject->getId();
        static::assertNotNull($identifier);

        $entityManager->clear();

        $reloaded = $entityManager->find(EncryptedSubject::class, $identifier);
        static::assertInstanceOf(EncryptedSubject::class, $reloaded);
        static::assertNull($reloaded->getRandomised());
        static::assertNull($reloaded->getDeterministicValue());
        static::assertNull($this->fetchRawRow($entityManager->getConnection(), $identifier)['randomised']);
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testDeterministicFieldIsMatchableInAWhereClause(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        foreach (['alpha@example.com', 'beta@example.com', 'gamma@example.com'] as $index => $value) {
            $entityManager->persist(
                (new EncryptedSubject())->setLabel('subject-' . $index)->setDeterministicValue($value),
            );
        }

        $entityManager->flush();
        $entityManager->clear();

        $entityService = $this->createEntityService($entityManager);

        $queryBuilder = $entityManager->createQueryBuilder()
            ->select('subject')
            ->from(EncryptedSubject::class, 'subject')
            ->where('subject.deterministicValue = :value');

        $entityService->setEncryptedParameter(
            $queryBuilder,
            'value',
            EncryptedSubject::class,
            'deterministicValue',
            'beta@example.com',
        );

        $matches = $queryBuilder->getQuery()->getResult();

        static::assertIsArray($matches);
        static::assertCount(1, $matches);
        static::assertInstanceOf(EncryptedSubject::class, $matches[0]);
        static::assertSame('subject-1', $matches[0]->getLabel());
        static::assertSame('beta@example.com', $matches[0]->getDeterministicValue());
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testRotationSafeLookupFindsRowsWrittenUnderThePreviousSalt(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        /* the pre-rotation row must be written under an explicit version, or it lands under `default` and there is nothing to rotate */
        IntegrationDatabase::registerTypes(
            new Aes256Encryptor(['v1' => IntegrationDatabase::SALT_V1], 'v1'),
            new Aes256FixedEncryptor(['v1' => IntegrationDatabase::SALT_V1], 'v1'),
        );

        $entityManager->persist((new EncryptedSubject())->setLabel('written-under-v1')->setDeterministicValue('rotating@example.com'));
        $entityManager->flush();
        $entityManager->clear();

        $rotatedEncryptor = new Aes256FixedEncryptor(
            ['v1' => IntegrationDatabase::SALT_V1, 'v2' => IntegrationDatabase::SALT_V2],
            'v2',
        );

        IntegrationDatabase::registerTypes(
            new Aes256Encryptor(['v1' => IntegrationDatabase::SALT_V1, 'v2' => IntegrationDatabase::SALT_V2], 'v2'),
            $rotatedEncryptor,
        );

        $entityManager->persist((new EncryptedSubject())->setLabel('written-under-v2')->setDeterministicValue('rotating@example.com'));
        $entityManager->flush();
        $entityManager->clear();

        $entityService = $this->createEntityService($entityManager, $rotatedEncryptor);

        $queryBuilder = $entityManager->createQueryBuilder()
            ->select('subject')
            ->from(EncryptedSubject::class, 'subject')
            ->where('subject.deterministicValue IN (:values)')
            ->orderBy('subject.label', 'ASC');

        $candidates = $entityService->setEncryptedParameterInList(
            $queryBuilder,
            'values',
            EncryptedSubject::class,
            'deterministicValue',
            'rotating@example.com',
        );

        static::assertCount(2, $candidates);
        static::assertNotSame($candidates[0], $candidates[1]);

        $matches = $queryBuilder->getQuery()->getResult();

        static::assertIsArray($matches);
        static::assertCount(2, $matches);
        static::assertSame('written-under-v1', $matches[0]->getLabel());
        static::assertSame('written-under-v2', $matches[1]->getLabel());

        static::assertSame('rotating@example.com', $matches[0]->getDeterministicValue());
        static::assertSame('rotating@example.com', $matches[1]->getDeterministicValue());
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testHasEncryptedValueInspectsTheRawColumn(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        $encryptedSubject = (new EncryptedSubject())->setLabel('raw-probe')->setRandomised('stored secret');

        $entityManager->persist($encryptedSubject);
        $entityManager->flush();

        $entityService = $this->createEntityService($entityManager);

        static::assertTrue($entityService->hasEncryptedValue($encryptedSubject, 'randomised'));
        static::assertFalse($entityService->hasEncryptedValue($encryptedSubject, 'label'));
        static::assertFalse($entityService->hasEncryptedValue(new EncryptedSubject(), 'randomised'));
    }

    /* ciphertext runs about 1.34x the plaintext plus roughly eighty bytes of envelope, against a column created at `AbstractType::DEFAULT_LENGTH` */
    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testDefaultLengthColumnOverflowsBeforeTheDeclaredPlaintextLength(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        $entityManager->persist(
            (new EncryptedSubject())->setLabel('overflow')->setDefaultLength(\str_repeat('p', 900)),
        );

        $thrown = null;

        try {
            $entityManager->flush();
        } catch (Throwable $throwable) {
            $thrown = $throwable;
        }

        static::assertNotNull(
            $thrown,
            'a 900-character plaintext encrypts to more than the 1000-character default column and must not be silently truncated',
        );
        static::assertStringContainsStringIgnoringCase('too long', $thrown->getMessage());

        /* a failed flush closes the manager, so teardown needs a fresh one before it can drop the schema */
        $this->entityManager = IntegrationDatabase::createEntityManager(
            IntegrationDatabase::createConnection($environmentVariable),
        );
    }

    #[DataProviderExternal(IntegrationDatabase::class, 'dataProviderEngine')]
    public function testDefaultLengthColumnAcceptsAPlaintextThatFits(string $environmentVariable): void
    {
        $entityManager = $this->boot($environmentVariable);

        $encryptedSubject = (new EncryptedSubject())->setLabel('fits')->setDefaultLength(\str_repeat('p', 600));

        $entityManager->persist($encryptedSubject);
        $entityManager->flush();

        $identifier = $encryptedSubject->getId();
        static::assertNotNull($identifier);

        $entityManager->clear();

        $reloaded = $entityManager->find(EncryptedSubject::class, $identifier);
        static::assertInstanceOf(EncryptedSubject::class, $reloaded);
        static::assertSame(\str_repeat('p', 600), $reloaded->getDefaultLength());
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

    private function createEntityService(
        EntityManagerInterface $entityManager,
        ?Aes256FixedEncryptor $deterministicEncryptor = null,
    ): EntityService {
        $encryptorFactory = new EncryptorFactory([
            new Aes256Encryptor(IntegrationDatabase::SALT_V1),
            $deterministicEncryptor ?? new Aes256FixedEncryptor(IntegrationDatabase::SALT_V1),
        ]);

        return new EntityService(new IntegrationManagerRegistry($entityManager), $encryptorFactory);
    }

    /** @return array<string, mixed> */
    private function fetchRawRow(Connection $connection, int $identifier): array
    {
        $row = $connection->fetchAssociative(
            'SELECT * FROM encrypted_subject WHERE id = :id',
            ['id' => $identifier],
        );

        static::assertIsArray($row);

        return $row;
    }
}
