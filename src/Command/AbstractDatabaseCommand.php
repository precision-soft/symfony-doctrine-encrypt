<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\DBAL\Types\Type;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\CheckpointScopeDto;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Symfony\Console\Command\AbstractCommand;
use Stringable;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Throwable;

abstract class AbstractDatabaseCommand extends AbstractCommand
{
    protected const OPTION_MANAGER = 'manager';
    protected const OPTION_BATCH_SIZE = 'batch-size';
    protected const OPTION_ENTITY = 'entity';
    protected const OPTION_FROM_ID = 'from-id';
    protected const OPTION_CHECKPOINT = 'checkpoint';
    protected const OPTION_DRY_RUN = 'dry-run';
    protected const BATCH_SIZE = 50;

    protected const INTEGER_TYPES = [Types::INTEGER, Types::SMALLINT, Types::BIGINT];
    protected const STRING_TYPES = [Types::STRING, Types::TEXT, Types::ASCII_STRING, Types::GUID];

    protected ?CheckpointService $checkpointService = null;

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
        $this->addOption(static::OPTION_BATCH_SIZE, null, InputOption::VALUE_REQUIRED, 'number of entities to process per batch', (string)static::BATCH_SIZE);
        $this->addOption(static::OPTION_ENTITY, null, InputOption::VALUE_REQUIRED, 'comma separated entity class names to restrict the run to, defaults to every entity with encrypted fields');
        $this->addOption(static::OPTION_FROM_ID, null, InputOption::VALUE_REQUIRED, 'resume after this identifier, requires a single `--entity` with a single identifier field');
        $this->addOption(static::OPTION_CHECKPOINT, null, InputOption::VALUE_REQUIRED, 'path to a json file holding the resume cursor, replaced atomically after every flushed batch');
        $this->addOption(static::OPTION_DRY_RUN, null, InputOption::VALUE_NONE, 'walk every selected row without writing entities or the checkpoint');
    }

    protected function initialize(InputInterface $input, OutputInterface $output): void
    {
        parent::initialize($input, $output);

        /* a command is a container service that outlives a run: the checkpoint of the previous run must not become the cursor of this one */
        $this->checkpointService = null;
    }

    protected function getStringOption(string $optionName): string
    {
        $value = $this->input->getOption($optionName);

        return true === \is_string($value) ? \trim($value) : '';
    }

    protected function getManagerName(): ?string
    {
        $managerName = $this->input->getOption(static::OPTION_MANAGER);

        return true === \is_string($managerName) ? $managerName : null;
    }

    /**
     * @throws Exception if the option is not a positive integer
     */
    protected function getBatchSize(): int
    {
        $batchSize = $this->input->getOption(static::OPTION_BATCH_SIZE);

        /* the cast saturates at PHP_INT_MAX instead of failing, and a saturated limit is one batch holding the whole table */
        if (
            false === \is_string($batchSize)
            || 1 !== \preg_match('/^[1-9]\d*$/', $batchSize)
            || (string)(int)$batchSize !== $batchSize
        ) {
            throw new Exception(
                \sprintf('the `--%s` option must be a positive integer', static::OPTION_BATCH_SIZE),
            );
        }

        return (int)$batchSize;
    }

    protected function getManager(): EntityManagerInterface
    {
        $objectManager = $this->managerRegistry->getManager($this->getManagerName());

        if (false === ($objectManager instanceof EntityManagerInterface)) {
            throw new Exception(\sprintf('expected an `EntityManagerInterface`, got `%s`', $objectManager::class));
        }

        return $objectManager;
    }

    protected function executeOperation(bool $decrypt): int
    {
        $direction = true === $decrypt ? 'decrypt' : 'encrypt';
        $sectionLabel = true === $decrypt ? 'DECRYPT' : 'ENCRYPT';

        try {
            $entitiesWithEncryption = $this->entityService->getEntitiesWithEncryption($this->getManagerName());
            $entitiesWithEncryption = $this->filterEntities($entitiesWithEncryption);

            if ([] === $entitiesWithEncryption) {
                $this->warning(\sprintf('no entities found to %s', $direction));

                throw new StopException();
            }

            $this->askForConfirmation($entitiesWithEncryption);
            $this->warning(\sprintf('%sing all the fields can take up to several minutes depending on the database size', $direction));

            foreach ($entitiesWithEncryption as $entityMetadataDto) {
                $this->processEntities($entityMetadataDto, $sectionLabel, $decrypt);
            }

            $this->afterOperation($entitiesWithEncryption);

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

        $batchSize = $this->getBatchSize();

        $entityManager = $this->getManager();
        /** @var EntityRepository<object> $repository */
        $repository = $entityManager->getRepository($className);

        $lastIdentifierValues = $this->getInitialIdentifierValues($entityMetadataDto);

        $countQueryBuilder = $repository->createQueryBuilder('e')
            ->select('COUNT(e)');

        /* the bar must count what this run will walk, not the table: on a resume every row before the cursor is already done */
        if (null !== $lastIdentifierValues) {
            $this->applyKeysetPagination($countQueryBuilder, $identifierFieldNames, $lastIdentifierValues);
        }

        $total = $countQueryBuilder->getQuery()->getSingleScalarResult();

        if (false === \is_numeric($total)) {
            throw new Exception('count query returned non-numeric result');
        }

        $progressBar = new ProgressBar($this->output, (int)$total);

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

            $queryBuilder->setMaxResults($batchSize);

            if (null !== $lastIdentifierValues) {
                $this->applyKeysetPagination($queryBuilder, $identifierFieldNames, $lastIdentifierValues);
            }

            try {
                $entities = $queryBuilder->getQuery()->getResult();
            } catch (Throwable $throwable) {
                throw new Exception(
                    \sprintf(
                        'loading a batch of `%s` %s failed: %s',
                        $className,
                        null === $lastIdentifierValues ? 'from the first row' : 'after the cursor `' . $this->describeCursor($lastIdentifierValues) . '`',
                        $throwable->getMessage(),
                    ),
                    0,
                    $throwable,
                    ['className' => $className, 'cursor' => $lastIdentifierValues],
                );
            }

            if ([] === $entities) {
                break;
            }

            $this->assertCursorAdvances($className, $lastIdentifierValues, $entityMetadataDto->getClassMetadata()->getIdentifierValues(\end($entities)));

            try {
                foreach ($entities as $entity) {
                    $lastIdentifierValues = $entityMetadataDto->getClassMetadata()->getIdentifierValues($entity);

                    if (true === $this->isDryRun()) {
                        $progressBar->advance();
                        continue;
                    }

                    $originalEntityData = $unitOfWork->getOriginalEntityData($entity);

                    foreach ($entityMetadataDto->getEncryptionFields() as $fieldName => $typeName) {
                        $originalEntityData[$fieldName] = null;
                    }

                    $unitOfWork->setOriginalEntityData($entity, $originalEntityData);
                    $entityManager->persist($entity);
                    $progressBar->advance();
                }

                /* the swap must wrap the flush alone: the SELECT above has to run with the real encryptor, or the plaintext it loaded would be re-encrypted on write */
                $resetEncryptors = true === $useFakeEncryptors
                    ? $this->resetEncryptorsToFake($entityMetadataDto->getEncryptionFields())
                    : null;

                try {
                    if (false === $this->isDryRun()) {
                        $entityManager->flush();
                    }
                } finally {
                    if (null !== $resetEncryptors) {
                        $this->restoreEncryptors($resetEncryptors);
                    }
                }
            } catch (Throwable $throwable) {
                $this->managerRegistry->resetManager($this->getManagerName());

                throw $throwable;
            }

            $this->onBatchProcessed($entityMetadataDto, $lastIdentifierValues);
            $entityManager->clear();
            \gc_collect_cycles();
        } while (true);

        $progressBar->finish();
        $this->writeln('');
    }

    protected function getCheckpointService(): CheckpointService
    {
        if (null !== $this->checkpointService) {
            return $this->checkpointService;
        }

        $path = $this->getStringOption(static::OPTION_CHECKPOINT);

        return $this->checkpointService = new CheckpointService(
            new CheckpointScopeDto(
                (string)$this->getName(),
                $this->getManagerName(),
                '' === $path ? '' : $this->getCurrentSaltVersion(),
            ),
            $path,
        );
    }

    /** the versions the registered types write with, so a checkpoint taken towards one salt is never resumed towards another */
    protected function getCurrentSaltVersion(): string
    {
        $saltVersions = [];

        foreach ($this->encryptorFactory->getTypeNames() as $typeName) {
            $encryptor = $this->encryptorFactory->getType($typeName)->getEncryptor();

            if (true === $encryptor instanceof AbstractEncryptor) {
                $saltVersions[] = $encryptor->getCurrentSaltVersion();
            }
        }

        $saltVersions = \array_values(\array_unique($saltVersions));
        \sort($saltVersions, \SORT_STRING);

        return \implode(',', $saltVersions);
    }

    /** @return string[] the class names given to `--entity`, an empty array when the run is not restricted */
    protected function getRequestedClassNames(): array
    {
        $requested = $this->getStringOption(static::OPTION_ENTITY);

        if ('' === $requested) {
            return [];
        }

        /* a class name copied out of an entity file carries a leading backslash, which ClassMetadata::getName() never does */

        return \array_values(
            \array_unique(
                \array_filter(
                    \array_map(
                        static fn(string $className): string => \ltrim(\trim($className), '\\'),
                        \explode(',', $requested),
                    ),
                    static fn(string $className): bool => '' !== $className,
                ),
            ),
        );
    }

    /**
     * @param EntityMetadataDto[] $entitiesWithEncryption
     * @return EntityMetadataDto[]
     *
     * @throws Exception if `--entity` names a class that has no encrypted field
     */
    protected function filterEntities(array $entitiesWithEncryption): array
    {
        $requestedClassNames = $this->getRequestedClassNames();

        if ([] === $requestedClassNames) {
            return $entitiesWithEncryption;
        }

        $filtered = \array_values(
            \array_filter(
                $entitiesWithEncryption,
                static fn(EntityMetadataDto $entityMetadataDto): bool => \in_array(
                    $entityMetadataDto->getClassMetadata()->getName(),
                    $requestedClassNames,
                    true,
                ),
            ),
        );

        $missingClassNames = \array_diff(
            $requestedClassNames,
            \array_map(
                static fn(EntityMetadataDto $entityMetadataDto): string => $entityMetadataDto->getClassMetadata()->getName(),
                $filtered,
            ),
        );

        if ([] !== $missingClassNames) {
            throw new Exception(
                \sprintf('no entity with encrypted fields found for `%s`', \implode('`, `', $missingClassNames)),
            );
        }

        return $filtered;
    }

    /**
     * @return array<string, mixed>|null
     *
     * @throws Exception if `--from-id` cannot address a single identifier field
     */
    protected function getInitialIdentifierValues(EntityMetadataDto $entityMetadataDto): ?array
    {
        $classMetadata = $entityMetadataDto->getClassMetadata();
        $fromId = $this->getStringOption(static::OPTION_FROM_ID);

        $identifierFieldNames = $classMetadata->getIdentifierFieldNames();

        if ('' === $fromId) {
            return $this->readCursor($classMetadata);
        }

        if (1 !== \count($this->getRequestedClassNames()) || 1 !== \count($identifierFieldNames)) {
            throw new Exception(
                \sprintf(
                    'the `--%s` option requires a single `--%s` with a single identifier field',
                    static::OPTION_FROM_ID,
                    static::OPTION_ENTITY,
                ),
            );
        }

        return [$identifierFieldNames[0] => $this->castIdentifierValue($classMetadata, $identifierFieldNames[0], $fromId)];
    }

    /**
     * @phpstan-param ClassMetadata<object> $classMetadata
     * @return array<string, mixed>|null
     *
     * @throws Exception if the stored cursor cannot address the entity's identifier
     */
    protected function readCursor(ClassMetadata $classMetadata): ?array
    {
        $className = $classMetadata->getName();
        $identifierFieldNames = $classMetadata->getIdentifierFieldNames();
        $identifierValues = $this->getCheckpointService()->getIdentifierValues($className);

        if (null === $identifierValues) {
            return null;
        }

        /* a cursor that misses an identifier field cannot be paginated on, and would silently rescan the table from the first row */
        $missingFieldNames = \array_diff($identifierFieldNames, \array_keys($identifierValues));

        if ([] !== $missingFieldNames) {
            throw new Exception(
                \sprintf(
                    'the checkpoint cursor for `%s` does not address `%s`',
                    $className,
                    \implode('`, `', $missingFieldNames),
                ),
            );
        }

        foreach ($identifierFieldNames as $identifierFieldName) {
            $value = $identifierValues[$identifierFieldName];

            if (false === \is_int($value) && false === \is_string($value)) {
                throw new Exception(
                    \sprintf(
                        'the checkpoint cursor for `%s` holds a value for `%s` that is not an integer or a string',
                        $className,
                        $identifierFieldName,
                    ),
                    0,
                    null,
                    ['className' => $className, 'fieldName' => $identifierFieldName, 'type' => \get_debug_type($value)],
                );
            }

            $identifierValues[$identifierFieldName] = $this->convertIdentifierValue($classMetadata, $identifierFieldName, $value);
        }

        return $identifierValues;
    }

    /**
     * @phpstan-param ClassMetadata<object> $classMetadata
     *
     * @throws Exception if the option cannot be represented as the identifier's mapped type
     */
    protected function castIdentifierValue(ClassMetadata $classMetadata, string $identifierFieldName, string $value): mixed
    {
        if (
            true === \in_array($classMetadata->getTypeOfField($identifierFieldName), static::INTEGER_TYPES, true)
            && 1 !== \preg_match('/^-?\d+$/', $value)
        ) {
            throw new Exception(
                \sprintf(
                    'the `--%s` option must be an integer for `%s::%s`',
                    static::OPTION_FROM_ID,
                    $classMetadata->getName(),
                    $identifierFieldName,
                ),
            );
        }

        return $this->convertIdentifierValue($classMetadata, $identifierFieldName, $value);
    }

    /**
     * An integer identifier bound as a string makes `id > :lastId` a cross-type comparison, which strict engines reject outright; an identifier of any other type is rebuilt through its own DBAL type, the value a stored string cannot be bound as.
     *
     * @phpstan-param ClassMetadata<object> $classMetadata
     *
     * @throws Exception if the identifier's type cannot rebuild the value
     */
    protected function convertIdentifierValue(ClassMetadata $classMetadata, string $identifierFieldName, int|string $value): mixed
    {
        $typeName = (string)$classMetadata->getTypeOfField($identifierFieldName);

        if (true === \in_array($typeName, static::INTEGER_TYPES, true)) {
            /* a bigint past PHP_INT_MAX stays the string DBAL itself hands back for it */
            return true === \is_string($value) && (string)(int)$value === $value ? (int)$value : $value;
        }

        if (true === \in_array($typeName, static::STRING_TYPES, true)) {
            return $value;
        }

        try {
            return Type::getType($typeName)->convertToPHPValue(
                $value,
                $this->getManager()->getConnection()->getDatabasePlatform(),
            );
        } catch (Throwable $throwable) {
            throw new Exception(
                \sprintf(
                    'the identifier value `%s` cannot be converted through the `%s` type of `%s::%s`',
                    $value,
                    $typeName,
                    $classMetadata->getName(),
                    $identifierFieldName,
                ),
                0,
                $throwable,
                ['className' => $classMetadata->getName(), 'fieldName' => $identifierFieldName, 'typeName' => $typeName],
            );
        }
    }

    /**
     * @param array<string, mixed> $identifierValues
     * @return array<string, int|string>
     *
     * @throws Exception if an identifier cannot be written into a checkpoint
     */
    protected function normalizeIdentifierValues(string $className, array $identifierValues): array
    {
        $normalized = [];

        foreach ($identifierValues as $fieldName => $value) {
            $normalized[$fieldName] = match (true) {
                true === \is_int($value), true === \is_string($value) => $value,
                true === $value instanceof Stringable => (string)$value,
                default => throw new Exception(
                    \sprintf('the identifier `%s` of `%s` is not an integer, a string or a `Stringable`; a checkpoint cannot address it', $fieldName, $className),
                    0,
                    null,
                    ['className' => $className, 'fieldName' => $fieldName, 'type' => \get_debug_type($value)],
                ),
            };
        }

        return $normalized;
    }

    /** @param array<string, mixed> $identifierValues */
    protected function describeCursor(array $identifierValues): string
    {
        $described = [];

        foreach ($identifierValues as $fieldName => $value) {
            $described[$fieldName] = match (true) {
                true === \is_int($value), true === \is_string($value), null === $value => $value,
                true === $value instanceof Stringable => (string)$value,
                default => \serialize($value),
            };
        }

        return (string)\json_encode($described);
    }

    /**
     * The loop's only exit is an empty batch, so a keyset that adds no predicate would hand the same rows back forever.
     *
     * @param array<string, mixed>|null $previousIdentifierValues
     * @param array<string, mixed> $identifierValues
     *
     * @throws Exception if the batch ends where the previous one did
     */
    protected function assertCursorAdvances(string $className, ?array $previousIdentifierValues, array $identifierValues): void
    {
        if (null === $previousIdentifierValues || $this->describeCursor($previousIdentifierValues) !== $this->describeCursor($identifierValues)) {
            return;
        }

        throw new Exception(
            \sprintf('the cursor for `%s` did not advance past `%s`; the identifier cannot be paginated on', $className, $this->describeCursor($identifierValues)),
            0,
            null,
            ['className' => $className, 'cursor' => $identifierValues],
        );
    }

    protected function isDryRun(): bool
    {
        return true === $this->input->getOption(static::OPTION_DRY_RUN);
    }

    /** @param array<string, mixed>|null $lastIdentifierValues */
    protected function onBatchProcessed(EntityMetadataDto $entityMetadataDto, ?array $lastIdentifierValues): void
    {
        if (true === $this->isDryRun() || null === $lastIdentifierValues || false === $this->getCheckpointService()->hasPath()) {
            return;
        }

        $className = $entityMetadataDto->getClassMetadata()->getName();

        $this->getCheckpointService()->setIdentifierValues(
            $className,
            $this->normalizeIdentifierValues($className, $lastIdentifierValues),
        );
    }

    /** @param EntityMetadataDto[] $entitiesWithEncryption */
    protected function afterOperation(array $entitiesWithEncryption): void
    {
        if (true === $this->isDryRun()) {
            return;
        }

        $this->getCheckpointService()->markCompleted(
            \array_map(
                static fn(EntityMetadataDto $entityMetadataDto): string => $entityMetadataDto->getClassMetadata()->getName(),
                $entitiesWithEncryption,
            ),
        );
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
            $value = $lastIdentifierValues[$identifierFieldName] ?? null;

            /* NULL is never greater than anything, so a null identifier cannot be paginated on */
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
            $value = $lastIdentifierValues[$identifierFieldName] ?? null;

            /* NULL is never greater than anything, so a null identifier cannot be paginated on */
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

        if ([] === $conditions) {
            return;
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
