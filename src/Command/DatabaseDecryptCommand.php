<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\UnitOfWork;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

class DatabaseDecryptCommand extends AbstractDatabaseCommand
{
    public const NAME = 'precision-soft:doctrine:database:decrypt';

    protected function configure(): void
    {
        parent::configure();

        $this->setName(self::NAME);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $entitiesWithEncryption = $this->entityService->getEntitiesWithEncryption($this->getManagerName());
            if (true === empty($entitiesWithEncryption)) {
                $this->warning('no entities found to decrypt');

                throw new StopException();
            }

            $this->askForConfirmation($entitiesWithEncryption);

            $this->warning('decrypting all the fields can take up to several minutes depending on the database size');

            foreach ($entitiesWithEncryption as $entityMetadataDto) {
                $this->decrypt($entityMetadataDto);
            }

            $this->success('decryption finished');
        } catch (StopException $t) {
            /* ignore */
        } catch (Throwable $t) {
            $this->error($t->getMessage(), $t);

            return static::FAILURE;
        }

        return static::SUCCESS;
    }

    private function decrypt(EntityMetadataDto $entityMetadataDto): void
    {
        $className = $entityMetadataDto->getClassMetadata()->getName();

        $this->style->section('[DECRYPT]' . $className);

        $fields = \array_merge(
            $entityMetadataDto->getClassMetadata()->getIdentifier(),
            \array_keys($entityMetadataDto->getEncryptionFields()),
        );

        $em = $this->getManager();
        /** @var UnitOfWork $unitOfWork */
        $unitOfWork = $em->getUnitOfWork();

        /** @var EntityRepository $repository */
        $repository = $em->getRepository($className);

        $total = $repository->createQueryBuilder('e')
            ->select('COUNT(e)')
            ->getQuery()->getSingleScalarResult();

        $progressBar = new ProgressBar($this->output, (int)$total);
        $i = 0;

        do {
            $entities = $repository->createQueryBuilder('e')
                ->select('PARTIAL e.{' . \implode(', ', $fields) . '}')
                ->setMaxResults(50)
                ->setFirstResult($i)
                ->getQuery()->getResult();

            $originalEntityData = $this->getOriginalEntityData($entityMetadataDto);

            $resetedEncryptors = $this->resetEncryptors($entityMetadataDto->getEncryptionFields());

            foreach ($entities as $entity) {
                ++$i;

                $unitOfWork->setOriginalEntityData($entity, $originalEntityData);

                $em->persist($entity);

                $progressBar->advance();
            }

            $em->flush();

            $this->restoreEncryptors($resetedEncryptors);

            $em->clear();
            \gc_collect_cycles();
        } while ($entities);

        $progressBar->finish();

        $this->writeln('');
    }

    private function resetEncryptors(array $encryptionFields): array
    {
        $resetedEncryptors = [];

        foreach ($encryptionFields as $typeName) {
            if (isset($resetedEncryptors[$typeName])) {
                continue;
            }

            $type = $this->encryptorFactory->getType($typeName);

            $resetedEncryptors[$typeName] = $type->getEncryptor();

            $type->setEncryptor(
                $this->encryptorFactory->getEncryptor(FakeEncryptor::class),
            );
        }

        return $resetedEncryptors;
    }

    private function restoreEncryptors(array $resetedEncryptors): void
    {
        foreach ($resetedEncryptors as $typeName => $encryptor) {
            $type = $this->encryptorFactory->getType($typeName);

            $type->setEncryptor($encryptor);
        }
    }
}
