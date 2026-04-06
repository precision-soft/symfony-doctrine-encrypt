<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Command;

use Doctrine\Persistence\ManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseDecryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @internal
 */
final class DatabaseDecryptCommandTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        return new MockDto(
            EntityService::class,
            [
                new MockDto(ManagerRegistry::class),
                new MockDto(EncryptorFactory::class),
            ],
        );
    }

    public function testCommandName(): void
    {
        static::assertSame(DatabaseDecryptCommand::NAME, 'precision-soft:doctrine:database:decrypt');
    }

    public function testExecuteWithNoEntitiesReturnsSuccess(): void
    {
        $entityService = $this->get(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andReturn([]);

        $databaseDecryptCommand = new DatabaseDecryptCommand(
            $this->get(ManagerRegistry::class),
            $this->get(EncryptorFactory::class),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseDecryptCommand);

        $commandTester = new CommandTester($databaseDecryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function testExecuteWithExceptionReturnsFailure(): void
    {
        $entityService = $this->get(EntityService::class);
        $entityService->shouldReceive('getEntitiesWithEncryption')
            ->once()
            ->andThrow(new Exception('database error'));

        $databaseDecryptCommand = new DatabaseDecryptCommand(
            $this->get(ManagerRegistry::class),
            $this->get(EncryptorFactory::class),
            $entityService,
        );

        $application = new Application();
        $application->addCommand($databaseDecryptCommand);

        $commandTester = new CommandTester($databaseDecryptCommand);
        $commandTester->execute([], ['interactive' => false]);

        static::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }
}
