<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: self::NAME)]
class DatabaseEncryptCommand extends AbstractDatabaseCommand
{
    public const NAME = 'precision-soft:doctrine:database:encrypt';

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        return $this->executeOperation(false);
    }
}
