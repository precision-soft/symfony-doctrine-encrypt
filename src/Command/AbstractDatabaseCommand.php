<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\ORM\UnitOfWork;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\ObjectManager;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Symfony\Console\Command\AbstractCommand;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Throwable;

abstract class AbstractDatabaseCommand extends AbstractCommand
{
    protected const OPTION_MANAGER = 'manager';

    public function __construct(
        protected readonly ManagerRegistry $managerRegistry,
        protected readonly EncryptorFactory $encryptorFactory,
        protected readonly EntityService $entityService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        parent::configure();

        $this->addOption(self::OPTION_MANAGER, null, InputOption::VALUE_OPTIONAL, 'the entity manager for which to run the command');
    }

    protected function getManagerName(): ?string
    {
        $managerName = $this->input->getOption(self::OPTION_MANAGER);

        return true === \is_string($managerName) ? $managerName : null;
    }

    protected function getManager(): ObjectManager
    {
        return $this->managerRegistry->getManager($this->getManagerName());
    }

    protected function processEntities(
        EntityMetadataDto $entityMetadataDto,
        string $sectionLabel,
        bool $useFakeEncryptors = false,
    ): void {
        $className = $entityMetadataDto->getClassMetadata()->getName();

        $this->style->section('[' . $sectionLabel . '] ' . $className);

        $identifierFieldNames = $entityMetadataDto->getClassMetadata()->getIdentifierFieldNames();

        $entityManager = $this->getManager();
        /** @var EntityRepository $repository */
        $repository = $entityManager->getRepository($className);

        $total = $repository->createQueryBuilder('e')
            ->select('COUNT(e)')
            ->getQuery()
            ->getSingleScalarResult();

        if (false === \is_numeric($total)) {
            throw new Exception('count query returned non-numeric result');
        }

        $progressBar = new ProgressBar($this->output, (int)$total);
        $lastIdentifierValues = null;

        $resetEncryptors = true === $useFakeEncryptors
            ? $this->resetEncryptorsToFake($entityMetadataDto->getEncryptionFields())
            : null;

        try {
            do {
                $entityManager = $this->getManager();
                /** @var UnitOfWork $unitOfWork */
                $unitOfWork = $entityManager->getUnitOfWork();

                /** @var EntityRepository $repository */
                $repository = $entityManager->getRepository($className);

                $queryBuilder = $repository->createQueryBuilder('e')
                    ->select('e');

                foreach ($identifierFieldNames as $identifierFieldName) {
                    $queryBuilder->addOrderBy('e.' . $identifierFieldName, 'ASC');
                }

                $queryBuilder->setMaxResults(50);

                if (null !== $lastIdentifierValues) {
                    $this->applyKeysetPagination($queryBuilder, $identifierFieldNames, $lastIdentifierValues);
                }

                $entities = $queryBuilder->getQuery()->getResult();

                if ([] === $entities) {
                    break;
                }

                try {
                    foreach ($entities as $entity) {
                        $lastIdentifierValues = $entityMetadataDto->getClassMetadata()->getIdentifierValues($entity);

                        $originalEntityData = $unitOfWork->getOriginalEntityData($entity);

                        foreach ($entityMetadataDto->getEncryptionFields() as $fieldName => $typeName) {
                            $originalEntityData[$fieldName] = null;
                        }

                        $unitOfWork->setOriginalEntityData($entity, $originalEntityData);
                        $entityManager->persist($entity);
                        $progressBar->advance();
                    }

                    $entityManager->flush();
                } catch (Throwable $throwable) {
                    $this->managerRegistry->resetManager($this->getManagerName());

                    throw $throwable;
                }

                $entityManager->clear();
                \gc_collect_cycles();
            } while (true);
        } finally {
            if (null !== $resetEncryptors) {
                $this->restoreEncryptors($resetEncryptors);
            }
        }

        $progressBar->finish();
        $this->writeln('');
    }

    /**
     * @param EntityMetadataDto[] $entitiesWithEncryption
     */
    protected function askForConfirmation(array $entitiesWithEncryption): void
    {
        if (false === $this->input->isInteractive()) {
            return;
        }

        $confirmationQuestion = new ConfirmationQuestion(
            $this->getQuestionText(
                [
                    \sprintf('`%s` entities found which are containing properties with encryption types.', \count($entitiesWithEncryption)),
                    'wrong settings can make your data unrecoverable.',
                    'i advise you to make a backup before running this command.',
                    'continue with this action? (y/yes)',
                ],
            ),
            false,
        );

        $questionHelper = $this->getHelper('question');

        if (false === $questionHelper->ask($this->input, $this->output, $confirmationQuestion)) {
            throw new StopException();
        }
    }

    /**
     * @param string[] $identifierFieldNames
     * @param array<string, mixed> $lastIdentifierValues
     */
    protected function applyKeysetPagination(
        QueryBuilder $queryBuilder,
        array $identifierFieldNames,
        array $lastIdentifierValues,
    ): void {
        if (1 === \count($identifierFieldNames)) {
            $identifierFieldName = $identifierFieldNames[0];
            $queryBuilder
                ->andWhere('e.' . $identifierFieldName . ' > :lastId')
                ->setParameter('lastId', $lastIdentifierValues[$identifierFieldName]);

            return;
        }

        $conditions = [];
        $previousFields = [];

        foreach ($identifierFieldNames as $index => $identifierFieldName) {
            $parameterName = 'lastId' . $index;
            $queryBuilder->setParameter($parameterName, $lastIdentifierValues[$identifierFieldName]);

            $equalParts = [];
            foreach ($previousFields as $previousIndex => $previousFieldName) {
                $equalParts[] = 'e.' . $previousFieldName . ' = :lastId' . $previousIndex;
            }

            $greaterPart = 'e.' . $identifierFieldName . ' > :' . $parameterName;

            $conditions[] = [] === $equalParts
                ? $greaterPart
                : '(' . \implode(' AND ', $equalParts) . ' AND ' . $greaterPart . ')';

            $previousFields[$index] = $identifierFieldName;
        }

        $queryBuilder->andWhere('(' . \implode(' OR ', $conditions) . ')');
    }

    /**
     * @param array<string, string> $encryptionFields
     *
     * @return array<string, EncryptorInterface>
     */
    protected function resetEncryptorsToFake(array $encryptionFields): array
    {
        $resetEncryptors = [];

        foreach ($encryptionFields as $typeName) {
            if (true === isset($resetEncryptors[$typeName])) {
                continue;
            }

            $abstractType = $this->encryptorFactory->getType($typeName);
            $resetEncryptors[$typeName] = $abstractType->getEncryptor();

            $abstractType->setEncryptor(
                $this->encryptorFactory->getEncryptor(FakeEncryptor::class),
            );
        }

        return $resetEncryptors;
    }

    /**
     * @param array<string, EncryptorInterface> $resetEncryptors
     */
    protected function restoreEncryptors(array $resetEncryptors): void
    {
        foreach ($resetEncryptors as $typeName => $encryptor) {
            $abstractType = $this->encryptorFactory->getType($typeName);
            $abstractType->setEncryptor($encryptor);
        }
    }

    /**
     * @param string[] $questionParts
     */
    protected function getQuestionText(array $questionParts): string
    {
        $maxLength = 0;

        foreach ($questionParts as $questionPart) {
            $maxLength = \max(\strlen($questionPart), $maxLength);
        }

        $indent = \str_repeat(' ', 4);

        foreach ($questionParts as &$questionPart) {
            $questionPart = $indent . \str_pad($questionPart, $maxLength, ' ');
        }

        unset($questionPart);

        return '<question>' . \implode(\PHP_EOL, $questionParts) . '</question>: ';
    }
}
