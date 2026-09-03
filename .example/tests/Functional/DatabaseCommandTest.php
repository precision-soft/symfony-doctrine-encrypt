<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Functional;

use PHPUnit\Framework\Attributes\DataProviderExternal;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseDecryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDatabase;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDirectoryTestCase;
use Symfony\Component\Console\Command\Command;

/** @internal */
final class DatabaseCommandTest extends CustomerDirectoryTestCase
{
    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testALegacyPlaintextTableIsEncryptedInPlaceAndDecryptedBack(string $environmentVariable): void
    {
        $kernel = $this->bootDirectory($environmentVariable);
        $connection = $this->getConnection($kernel);
        $customerDirectory = $this->getDirectory($kernel);

        /* the directory before the bundle: rows written in plaintext by the previous application */
        foreach (['Ada', 'Grace', 'Linus'] as $index => $displayName) {
            $connection->insert('customer_user', [
                'displayName' => $displayName,
                'email' => \strtolower($displayName) . '@example.com',
                'phone' => '+40 700 000 00' . $index,
                'address' => null,
            ]);
        }

        $ada = $customerDirectory->findById(1);

        static::assertFalse($customerDirectory->hasStoredCiphertext($ada, 'email'));
        static::assertSame('ada@example.com', $ada->getEmail(), 'plaintext is read back as it is, so the switch-over needs no downtime');

        $commandTester = $this->runCommand($kernel, DatabaseEncryptCommand::NAME, ['--batch-size' => '2', '--checkpoint' => $this->checkpointPath]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());

        foreach ([1, 2, 3] as $id) {
            $storedRow = CustomerDatabase::fetchStoredRow($connection, $id);

            $this->assertStoredAsCiphertext($storedRow['email'], $this->getCurrentEnvelopePrefix($kernel, 'encryptedAes256fixed'));
            $this->assertStoredAsCiphertext($storedRow['phone'], $this->getCurrentEnvelopePrefix($kernel));
        }

        static::assertTrue($customerDirectory->hasStoredCiphertext($ada, 'email'));
        static::assertNotNull($customerDirectory->findByEmail('grace@example.com'));

        /* a second run finds nothing left to do: the deterministic column is byte-stable across runs */
        $emailBefore = CustomerDatabase::fetchStoredRow($connection, 2)['email'];

        static::assertSame(Command::SUCCESS, $this->runCommand($kernel, DatabaseEncryptCommand::NAME)->getStatusCode());
        static::assertSame($emailBefore, CustomerDatabase::fetchStoredRow($connection, 2)['email']);

        $commandTester = $this->runCommand($kernel, DatabaseDecryptCommand::NAME);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertSame('grace@example.com', CustomerDatabase::fetchStoredRow($connection, 2)['email']);
        static::assertSame('+40 700 000 002', CustomerDatabase::fetchStoredRow($connection, 3)['phone']);
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testADryRunWalksTheRowsAndWritesNothing(string $environmentVariable): void
    {
        $kernel = $this->bootDirectory($environmentVariable);
        $connection = $this->getConnection($kernel);

        $connection->insert('customer_user', ['displayName' => 'Ada', 'email' => 'ada@example.com', 'phone' => '+40 700 000 001', 'address' => null]);

        $commandTester = $this->runCommand($kernel, DatabaseEncryptCommand::NAME, ['--dry-run' => true, '--checkpoint' => $this->checkpointPath]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertSame('ada@example.com', CustomerDatabase::fetchStoredRow($connection, 1)['email']);
        static::assertFileDoesNotExist($this->checkpointPath);
    }
}
