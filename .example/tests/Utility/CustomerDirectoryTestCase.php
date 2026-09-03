<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility;

use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Example\CustomerDirectoryKernel;
use PrecisionSoft\Doctrine\Encrypt\Example\Service\CustomerDirectory;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Boots the directory the way an application would - through the kernel, so the bundle registers the types itself - once per salt generation; the schema is created by the first boot of a test and dropped afterwards.
 *
 * @internal
 */
abstract class CustomerDirectoryTestCase extends TestCase
{
    protected const GENERATION_FIRST = 'v1';
    protected const GENERATION_SECOND = 'v2';

    /** @var list<CustomerDirectoryKernel> */
    protected array $kernels = [];

    protected string $checkpointPath = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->checkpointPath = \sys_get_temp_dir() . '/customer-directory-' . \bin2hex(\random_bytes(8)) . '.json';
    }

    protected function tearDown(): void
    {
        if (true === \is_file($this->checkpointPath)) {
            \unlink($this->checkpointPath);
        }

        foreach ($this->kernels as $index => $kernel) {
            if (0 === $index) {
                CustomerDatabase::dropSchema($this->getEntityManager($kernel));
            }

            $this->getEntityManager($kernel)->getConnection()->close();
            $kernel->shutdown();
        }

        $this->kernels = [];

        parent::tearDown();
    }

    /**
     * `v1` is the directory as first deployed; `v2` is the same directory after the salt flip, with the previous salt kept for reads.
     */
    protected function bootDirectory(string $environmentVariable, string $generation = self::GENERATION_FIRST): CustomerDirectoryKernel
    {
        try {
            $databaseUrl = CustomerDatabase::getDatabaseUrl($environmentVariable);
        } catch (SkipException $skipException) {
            static::markTestSkipped($skipException->getMessage());
        }

        $environment = \strtolower($environmentVariable) . '_' . $generation;

        (new Filesystem())->remove(\dirname(__DIR__, 2) . '/var/cache/' . $environment);

        $kernel = static::GENERATION_FIRST === $generation
            ? new CustomerDirectoryKernel($environment, $databaseUrl, ['v1' => CustomerDatabase::SALT_V1], 'v1')
            : new CustomerDirectoryKernel($environment, $databaseUrl, ['v1' => CustomerDatabase::SALT_V1, 'v2' => CustomerDatabase::SALT_V2], 'v2', 'v1');

        $kernel->boot();

        if ([] === $this->kernels) {
            CustomerDatabase::createSchema($this->getEntityManager($kernel));
        }

        $this->kernels[] = $kernel;

        return $kernel;
    }

    protected function getDirectory(CustomerDirectoryKernel $kernel): CustomerDirectory
    {
        $customerDirectory = $kernel->getContainer()->get(CustomerDirectory::class);

        static::assertInstanceOf(CustomerDirectory::class, $customerDirectory);

        return $customerDirectory;
    }

    protected function getEntityManager(CustomerDirectoryKernel $kernel): EntityManagerInterface
    {
        $managerRegistry = $kernel->getContainer()->get('doctrine');

        static::assertInstanceOf(ManagerRegistry::class, $managerRegistry);

        $entityManager = $managerRegistry->getManager();

        static::assertInstanceOf(EntityManagerInterface::class, $entityManager);

        return $entityManager;
    }

    protected function getConnection(CustomerDirectoryKernel $kernel): Connection
    {
        return $this->getEntityManager($kernel)->getConnection();
    }

    /**
     * the prefix every value written by this kernel carries: the marker, the format version and the current salt version
     *
     * @return non-empty-string
     */
    protected function getCurrentEnvelopePrefix(CustomerDirectoryKernel $kernel, string $typeName = 'encryptedAes256'): string
    {
        $encryptorFactory = $kernel->getContainer()->get(EncryptorFactory::class);

        static::assertInstanceOf(EncryptorFactory::class, $encryptorFactory);

        $encryptor = $encryptorFactory->getEncryptorByType($typeName);

        static::assertInstanceOf(AbstractEncryptor::class, $encryptor);

        $envelopePrefix = $encryptor->getCurrentEnvelopePrefix();

        if ('' === $envelopePrefix) {
            static::fail('an encryptor never writes an empty envelope prefix');
        }

        return $envelopePrefix;
    }

    /** @param array<string, mixed> $input */
    protected function runCommand(CustomerDirectoryKernel $kernel, string $name, array $input = []): CommandTester
    {
        $application = new Application($kernel);
        $application->setAutoExit(false);

        $commandTester = new CommandTester($application->find($name));
        $commandTester->execute($input, ['interactive' => false]);

        return $commandTester;
    }

    /** @param non-empty-string $envelopePrefix */
    protected function assertStoredAsCiphertext(mixed $storedValue, string $envelopePrefix): void
    {
        static::assertIsString($storedValue);
        static::assertStringStartsWith($envelopePrefix, $storedValue);
        static::assertCount(6, \explode(AbstractEncryptor::GLUE, $storedValue));
    }
}
