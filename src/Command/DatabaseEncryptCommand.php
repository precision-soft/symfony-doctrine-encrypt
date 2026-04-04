<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\UnitOfWork;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

#[AsCommand(name: self::NAME)]
class DatabaseEncryptCommand extends AbstractDatabaseCommand
{
    public const NAME = 'precision-soft:doctrine:database:encrypt';

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $entitiesWithEncryption = $this->entityService->getEntitiesWithEncryption($this->getManagerName());

            if ([] === $entitiesWithEncryption) {
                $this->warning('no entities found to encrypt');

                throw new StopException();
            }

            $this->askForConfirmation($entitiesWithEncryption);
            $this->warning('encrypting all the fields can take up to several minutes depending on the database size');

            foreach ($entitiesWithEncryption as $entityMetadataDto) {
                $this->encrypt($entityMetadataDto);
            }

            $this->success('encryption finished');
        } catch (StopException) {
        } catch (Throwable $throwable) {
            $this->error($throwable->getMessage(), $throwable);

            return static::FAILURE;
        }

        return static::SUCCESS;
    }

    private function encrypt(EntityMetadataDto $entityMetadataDto): void
    {
        $className = $entityMetadataDto->getClassMetadata()->getName();

        $this->style->section('[ENCRYPT] ' . $className);

        $entityManager = $this->getManager();
        /** @var UnitOfWork $unitOfWork */
        $unitOfWork = $entityManager->getUnitOfWork();

        /** @var EntityRepository $repository */
        $repository = $entityManager->getRepository($className);

        $total = $repository->createQueryBuilder('e')
            ->select('COUNT(e)')
            ->getQuery()
            ->getSingleScalarResult();

        $progressBar = new ProgressBar($this->output, (int)$total);
        $offset = 0;

        do {
            $entities = $repository->createQueryBuilder('e')
                ->select('e')
                ->setMaxResults(50)
                ->setFirstResult($offset)
                ->getQuery()
                ->getResult();

            $originalEntityData = $this->getOriginalEntityData($entityMetadataDto);

            foreach ($entities as $entity) {
                ++$offset;

                $unitOfWork->setOriginalEntityData($entity, $originalEntityData);
                $entityManager->persist($entity);
                $progressBar->advance();
            }

            $entityManager->flush();
            $entityManager->clear();
            \gc_collect_cycles();
        } while ([] !== $entities);

        $progressBar->finish();
        $this->writeln('');
    }
}
