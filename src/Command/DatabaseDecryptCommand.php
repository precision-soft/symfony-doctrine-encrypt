<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\UnitOfWork;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

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
                $this->decrypt($entityMetadataDto);
            }

            $this->success('decryption finished');
        } catch (StopException) {
        } catch (Throwable $throwable) {
            $this->error($throwable->getMessage(), $throwable);

            return static::FAILURE;
        }

        return static::SUCCESS;
    }

    private function decrypt(EntityMetadataDto $entityMetadataDto): void
    {
        $className = $entityMetadataDto->getClassMetadata()->getName();

        $this->style->section('[DECRYPT] ' . $className);

        $fields = \array_merge(
            $entityMetadataDto->getClassMetadata()->getIdentifier(),
            \array_keys($entityMetadataDto->getEncryptionFields()),
        );

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
                ->select('PARTIAL e.{' . \implode(', ', $fields) . '}')
                ->setMaxResults(50)
                ->setFirstResult($offset)
                ->getQuery()
                ->getResult();

            $originalEntityData = $this->getOriginalEntityData($entityMetadataDto);
            $resetEncryptors = $this->resetEncryptors($entityMetadataDto->getEncryptionFields());

            foreach ($entities as $entity) {
                ++$offset;

                $unitOfWork->setOriginalEntityData($entity, $originalEntityData);
                $entityManager->persist($entity);
                $progressBar->advance();
            }

            $entityManager->flush();
            $this->restoreEncryptors($resetEncryptors);
            $entityManager->clear();
            \gc_collect_cycles();
        } while ([] !== $entities);

        $progressBar->finish();
        $this->writeln('');
    }

    /**
     * @param array<string, string> $encryptionFields
     *
     * @return array<string, EncryptorInterface>
     */
    private function resetEncryptors(array $encryptionFields): array
    {
        $resetEncryptors = [];

        foreach ($encryptionFields as $typeName) {
            if (true === isset($resetEncryptors[$typeName])) {
                continue;
            }

            $type = $this->encryptorFactory->getType($typeName);
            $resetEncryptors[$typeName] = $type->getEncryptor();

            $type->setEncryptor(
                $this->encryptorFactory->getEncryptor(FakeEncryptor::class),
            );
        }

        return $resetEncryptors;
    }

    /**
     * @param array<string, EncryptorInterface> $resetEncryptors
     */
    private function restoreEncryptors(array $resetEncryptors): void
    {
        foreach ($resetEncryptors as $typeName => $encryptor) {
            $type = $this->encryptorFactory->getType($typeName);
            $type->setEncryptor($encryptor);
        }
    }
}
