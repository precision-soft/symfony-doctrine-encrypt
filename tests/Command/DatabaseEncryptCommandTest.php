<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Command;

use Doctrine\Persistence\ManagerRegistry;
use Mockery;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
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
    public function testCommandName(): void
    {
        static::assertSame(DatabaseEncryptCommand::NAME, 'precision-soft:doctrine:database:encrypt');
    }

    public function testExecuteWithNoEntitiesReturnsSuccess(): void
    {
        $registry = Mockery::mock(ManagerRegistry::class);
        $factory = Mockery::mock(EncryptorFactory::class);
        $entityService = Mockery::mock(EntityService::class);

        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([]);

        $command = new DatabaseEncryptCommand($registry, $factory, $entityService);

        $application = new Application();
        $application->addCommand($command);

        $commandTester = new CommandTester($command);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testExecuteWithExceptionReturnsFailure(): void
    {
        $registry = Mockery::mock(ManagerRegistry::class);
        $factory = Mockery::mock(EncryptorFactory::class);
        $entityService = Mockery::mock(EntityService::class);

        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andThrow(new \RuntimeException('database error'));

        $command = new DatabaseEncryptCommand($registry, $factory, $entityService);

        $application = new Application();
        $application->addCommand($command);

        $commandTester = new CommandTester($command);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }
}
