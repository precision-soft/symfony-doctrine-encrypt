<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Functional;

use PHPUnit\Framework\Attributes\DataProviderExternal;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseRotateCommand;
use PrecisionSoft\Doctrine\Encrypt\Dto\CheckpointScopeDto;
use PrecisionSoft\Doctrine\Encrypt\Example\Entity\User;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDatabase;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDirectoryTestCase;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;
use Symfony\Component\Console\Command\Command;

/** @internal */
final class CheckpointTest extends CustomerDirectoryTestCase
{
    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testAnInterruptedRotationResumesAfterTheLastFlushedRow(string $environmentVariable): void
    {
        $firstDirectory = $this->getDirectory($this->bootDirectory($environmentVariable));

        $ada = $firstDirectory->register('Ada', 'ada@example.com', '+40 700 000 001');
        $grace = $firstDirectory->register('Grace', 'grace@example.com', '+40 700 000 002');

        static::assertIsInt($ada->getId());
        static::assertIsInt($grace->getId());

        $secondGeneration = $this->bootDirectory($environmentVariable, self::GENERATION_SECOND);
        $connection = $this->getConnection($secondGeneration);
        $secondPrefix = $this->getCurrentEnvelopePrefix($secondGeneration);

        /* the file a run leaves behind when it dies after its first batch: the cursor sits on Ada, the class is not completed */
        $scope = new CheckpointScopeDto(DatabaseRotateCommand::NAME, null, 'v2');
        (new CheckpointService($scope, $this->checkpointPath))->setIdentifierValues(User::class, ['id' => $ada->getId()]);

        $commandTester = $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, ['--checkpoint' => $this->checkpointPath]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertStringStartsNotWith($secondPrefix, (string)CustomerDatabase::fetchStoredRow($connection, $ada->getId())['phone'], 'the rows before the cursor are the previous run\'s work');
        $this->assertStoredAsCiphertext(CustomerDatabase::fetchStoredRow($connection, $grace->getId())['phone'], $secondPrefix);

        $decoded = \json_decode((string)\file_get_contents($this->checkpointPath), true, 512, \JSON_THROW_ON_ERROR);

        static::assertIsArray($decoded);
        static::assertSame(CheckpointService::FORMAT_VERSION, $decoded['version']);
        static::assertSame($scope->toArray(), $decoded['scope']);
        static::assertSame([User::class], $decoded['completed']);

        /* the completed class starts over on the next run with the same file, which is how the skipped row is picked up */
        $commandTester = $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, ['--checkpoint' => $this->checkpointPath, '--verify' => true]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode(), $commandTester->getDisplay());
        $this->assertStoredAsCiphertext(CustomerDatabase::fetchStoredRow($connection, $ada->getId())['phone'], $secondPrefix);
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testACheckpointBelongsToTheCommandAndTheSaltThatWroteIt(string $environmentVariable): void
    {
        $this->getDirectory($this->bootDirectory($environmentVariable))->register('Ada', 'ada@example.com', '+40 700 000 001');

        $secondGeneration = $this->bootDirectory($environmentVariable, self::GENERATION_SECOND);

        static::assertSame(
            Command::SUCCESS,
            $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, ['--checkpoint' => $this->checkpointPath])->getStatusCode(),
        );

        $commandTester = $this->runCommand($secondGeneration, DatabaseEncryptCommand::NAME, ['--checkpoint' => $this->checkpointPath]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertStringContainsString('was written by', (string)\preg_replace('/\s+/', ' ', $commandTester->getDisplay()));

        /* the file of a rotation towards the previous salt: resuming it now would leave every row before its cursor on `v1` */
        \unlink($this->checkpointPath);
        (new CheckpointService(new CheckpointScopeDto(DatabaseRotateCommand::NAME, null, 'v1'), $this->checkpointPath))
            ->setIdentifierValues(User::class, ['id' => 1]);

        $commandTester = $this->runCommand($secondGeneration, DatabaseRotateCommand::NAME, ['--checkpoint' => $this->checkpointPath]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode(), $commandTester->getDisplay());
        static::assertStringContainsString('was written towards the salt version', (string)\preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }
}
