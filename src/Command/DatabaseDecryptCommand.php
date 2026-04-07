<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: self::NAME)]
class DatabaseDecryptCommand extends AbstractDatabaseCommand
{
    public const NAME = 'precision-soft:doctrine:database:decrypt';

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $entitiesWithEncryption = $this->entityService->getEntitiesWithEncryption($this->getManagerName());

            if ([] === $entitiesWithEncryption) {
                $this->warning('no entities found to decrypt');

                throw new StopException();
            }

            $this->askForConfirmation($entitiesWithEncryption);
            $this->warning('decrypting all the fields can take up to several minutes depending on the database size');

            foreach ($entitiesWithEncryption as $entityMetadataDto) {
                $this->processEntities($entityMetadataDto, 'DECRYPT', true);
            }

            $this->success('decryption finished');
        } catch (StopException) {
        } catch (Exception $exception) {
            $this->error($exception->getMessage(), $exception);

            return static::FAILURE;
        }

        return static::SUCCESS;
    }
}
