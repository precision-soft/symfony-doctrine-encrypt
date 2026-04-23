<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Symfony\Console\Command\AbstractCommand;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Throwable;

abstract class AbstractDatabaseCommand extends AbstractCommand
{
    protected const OPTION_MANAGER = 'manager';
    protected const BATCH_SIZE = 50;

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

        $this->addOption(static::OPTION_MANAGER, null, InputOption::VALUE_OPTIONAL, 'the entity manager for which to run the command');
    }

    protected function getManagerName(): ?string
    {
        $managerName = $this->input->getOption(static::OPTION_MANAGER);

        return true === \is_string($managerName) ? $managerName : null;
    }

    protected function getManager(): EntityManagerInterface
    {
        $objectManager = $this->managerRegistry->getManager($this->getManagerName());

        if (false === ($objectManager instanceof EntityManagerInterface)) {
            throw new Exception(\sprintf('expected EntityManagerInterface, got `%s`', $objectManager::class));
        }

        return $objectManager;
    }

    protected function executeOperation(bool $decrypt): int
    {
        $direction = true === $decrypt ? 'decrypt' : 'encrypt';
        $sectionLabel = true === $decrypt ? 'DECRYPT' : 'ENCRYPT';

        try {
            $entitiesWithEncryption = $this->entityService->getEntitiesWithEncryption($this->getManagerName());

            if ([] === $entitiesWithEncryption) {
                $this->warning(\sprintf('no entities found to %s', $direction));

                throw new StopException();
            }

            $this->askForConfirmation($entitiesWithEncryption);
            $this->warning(\sprintf('%sing all the fields can take up to several minutes depending on the database size', $direction));

            foreach ($entitiesWithEncryption as $entityMetadataDto) {
                $this->processEntities($entityMetadataDto, $sectionLabel, $decrypt);
            }

            $this->success(\sprintf('%sion finished', $direction));
        } catch (StopException) {
        } catch (Throwable $throwable) {
            $this->error($throwable->getMessage(), $throwable);

            return static::FAILURE;
        }

        return static::SUCCESS;
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
        /** @var EntityRepository<object> $repository */
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

        do {
            $entityManager = $this->getManager();
            $unitOfWork = $entityManager->getUnitOfWork();

            /** @var EntityRepository<object> $repository */
            $repository = $entityManager->getRepository($className);

            $queryBuilder = $repository->createQueryBuilder('e')
                ->select('e');

            foreach ($identifierFieldNames as $identifierFieldName) {
                $queryBuilder->addOrderBy('e.' . $identifierFieldName, 'ASC');
            }

            $queryBuilder->setMaxResults(static::BATCH_SIZE);

            if (null !== $lastIdentifierValues) {
                $this->applyKeysetPagination($queryBuilder, $identifierFieldNames, $lastIdentifierValues);
            }

            /** @info SELECT runs with the real encryptor so entity properties hold plaintext (or pass-through on non-encrypted data); the FakeEncryptor swap is intentionally deferred until the flush phase below */
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

                /** @info for the decrypt path, swap to FakeEncryptor only around flush so plaintext from the SELECT phase above is written back unchanged */
                $resetEncryptors = true === $useFakeEncryptors
                    ? $this->resetEncryptorsToFake($entityMetadataDto->getEncryptionFields())
                    : null;

                try {
                    $entityManager->flush();
                } finally {
                    if (null !== $resetEncryptors) {
                        $this->restoreEncryptors($resetEncryptors);
                    }
                }
            } catch (Throwable $throwable) {
                $this->managerRegistry->resetManager($this->getManagerName());

                throw $throwable;
            }

            $entityManager->clear();
            \gc_collect_cycles();
        } while (true);

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
        \assert($questionHelper instanceof QuestionHelper);

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
            $value = $lastIdentifierValues[$identifierFieldName];

            /** @info skip keyset pagination for null identifiers — null PKs cannot be compared with > */
            if (null === $value) {
                return;
            }

            $queryBuilder
                ->andWhere('e.' . $identifierFieldName . ' > :lastId')
                ->setParameter('lastId', $value);

            return;
        }

        $conditions = [];
        $previousFields = [];

        foreach ($identifierFieldNames as $index => $identifierFieldName) {
            $value = $lastIdentifierValues[$identifierFieldName];

            /** @info skip keyset pagination for null identifiers — null PKs cannot be compared with > */
            if (null === $value) {
                continue;
            }

            $parameterName = 'lastId' . $index;
            $queryBuilder->setParameter($parameterName, $value);

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
