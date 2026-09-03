<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Functional;

use PHPUnit\Framework\Attributes\DataProviderExternal;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseRotateCommand;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDatabase;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDirectoryTestCase;
use Symfony\Component\Console\Command\Command;

/** @internal */
final class SaltRotationTest extends CustomerDirectoryTestCase
{
    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testTheDirectoryIsRotatedOnlineToTheNextSalt(string $environmentVariable): void
    {
        $firstGeneration = $this->bootDirectory($environmentVariable);
        $firstDirectory = $this->getDirectory($firstGeneration);

        $ada = $firstDirectory->register('Ada', 'ada@example.com', '+40 700 000 001', '1 Analytical Lane');
        $grace = $firstDirectory->register('Grace', 'grace@example.com', '+40 700 000 002');

        static::assertIsInt($ada->getId());
        static::assertIsInt($grace->getId());

        $firstPrefix = $this->getCurrentEnvelopePrefix($firstGeneration);

        /* step 1 of the online rotation: the new salt is current, the old one stays readable */
        $secondGeneration = $this->bootDirectory($environmentVariable, self::GENERATION_SECOND);
        $secondDirectory = $this->getDirectory($secondGeneration);
        $connection = $this->getConnection($secondGeneration);
        $secondPrefix = $this->getCurrentEnvelopePrefix($secondGeneration);

        static::assertNotSame($firstPrefix, $secondPrefix);
        static::assertSame('1 Analytical Lane', $secondDirectory->findById($ada->getId())->getAddress(), 'a row under the previous salt still reads');

        /* the check before the rotation: nothing is written and the stale rows are reported */
        $commandTester = $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, ['--dry-run' => true, '--verify' => true]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertStringContainsString('rotation verification failed', $commandTester->getDisplay());
        $this->assertStoredAsCiphertext(CustomerDatabase::fetchStoredRow($connection, $ada->getId())['email'], $firstPrefix);

        /* step 2: every row is rewritten under the current salt, in batches, with a checkpoint, and verified */
        $commandTester = $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, [
            '--batch-size' => '1',
            '--checkpoint' => $this->checkpointPath,
            '--verify' => true,
        ]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());

        foreach ([$ada->getId(), $grace->getId()] as $id) {
            $storedRow = CustomerDatabase::fetchStoredRow($connection, $id);

            $this->assertStoredAsCiphertext($storedRow['email'], $this->getCurrentEnvelopePrefix($secondGeneration, 'encryptedAes256fixed'));
            $this->assertStoredAsCiphertext($storedRow['phone'], $secondPrefix);
        }

        /* the plain lookup works again, because the deterministic column now carries the current salt */
        $this->getEntityManager($secondGeneration)->clear();

        $found = $secondDirectory->findByEmail('grace@example.com');

        static::assertNotNull($found);
        static::assertSame('Grace', $found->getDisplayName());
        static::assertSame('1 Analytical Lane', $secondDirectory->findById($ada->getId())->getAddress());

        /* the check after the rotation is the proof step 3 - dropping the old salt - waits for */
        $commandTester = $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, ['--dry-run' => true, '--verify' => true]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertStringContainsString('rotation verification passed', $commandTester->getDisplay());
    }
}
