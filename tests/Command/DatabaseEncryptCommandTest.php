<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Command;

use Doctrine\Persistence\ManagerRegistry;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @internal
 */
final class DatabaseEncryptCommandTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testCommandName(): void
    {
        static::assertSame(DatabaseEncryptCommand::NAME, 'precision-soft:doctrine:database:encrypt');
    }

    public function testExecuteWithNoEntitiesReturnsSuccess(): void
    {
        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $entityService = Mockery::mock(EntityService::class);

        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([]);

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testExecuteWithExceptionReturnsFailure(): void
    {
        $managerRegistry = Mockery::mock(ManagerRegistry::class);
        $encryptorFactory = Mockery::mock(EncryptorFactory::class);
        $entityService = Mockery::mock(EntityService::class);

        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andThrow(new Exception('database error'));

        $databaseEncryptCommand = new DatabaseEncryptCommand($managerRegistry, $encryptorFactory, $entityService);

        $application = new Application();
        $application->addCommand($databaseEncryptCommand);

        $commandTester = new CommandTester($databaseEncryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }
}
