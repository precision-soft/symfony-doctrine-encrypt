<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: self::NAME)]
class DatabaseRotateCommand extends AbstractDatabaseCommand
{
    public const NAME = 'precision-soft:doctrine:database:rotate';

    protected const OPTION_VERIFY = 'verify';

    /* an envelope prefix is `<ENC>`, NUL, a format version and a salt version matching [A-Za-z0-9_.-], so `!` can never occur inside one and stays a safe LIKE escape whatever NO_BACKSLASH_ESCAPES is set to */
    protected const LIKE_ESCAPE_CHARACTER = '!';

    protected function configure(): void
    {
        parent::configure();

        $this->addOption(static::OPTION_VERIFY, null, InputOption::VALUE_NONE, 'read the stored columns of the selected entities back and fail unless every value carries the current salt version; with `--dry-run` nothing is written and the check still runs');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        return $this->executeOperation(false);
    }

    /** @param EntityMetadataDto[] $entitiesWithEncryption */
    protected function afterOperation(array $entitiesWithEncryption): void
    {
        parent::afterOperation($entitiesWithEncryption);

        if (true === $this->input->getOption(static::OPTION_VERIFY)) {
            $this->verifyCurrentSalt($entitiesWithEncryption);
        }
    }

    /**
     * @param EntityMetadataDto[] $entitiesWithEncryption
     *
     * @throws Exception if any stored value of the selected entities is still under another salt version
     */
    protected function verifyCurrentSalt(array $entitiesWithEncryption): void
    {
        $entityManager = $this->getManager();
        $connection = $entityManager->getConnection();
        $platform = $connection->getDatabasePlatform();

        $failures = [];

        foreach ($entitiesWithEncryption as $entityMetadataDto) {
            $classMetadata = $entityMetadataDto->getClassMetadata();

            if (false === ($classMetadata instanceof OrmClassMetadata)) {
                throw new Exception(\sprintf('expected an orm `ClassMetadata`, got `%s`', $classMetadata::class));
            }

            foreach ($entityMetadataDto->getEncryptionFields() as $fieldName => $typeName) {
                $encryptor = $this->encryptorFactory->getType($typeName)->getEncryptor();

                if (false === ($encryptor instanceof AbstractEncryptor)) {
                    throw new Exception(\sprintf('the encryptor for type `%s` does not expose a salt version', $typeName));
                }

                $staleCount = $this->countValuesOffCurrentSalt($connection, $platform, $classMetadata, $fieldName, $encryptor);

                if (0 < $staleCount) {
                    $failures[] = \sprintf('%s::%s (%d rows)', $classMetadata->getName(), $fieldName, $staleCount);
                }
            }
        }

        if ([] !== $failures) {
            throw new Exception('rotation verification failed for ' . \implode(', ', $failures));
        }

        $this->success('rotation verification passed');
    }

    /** @phpstan-param OrmClassMetadata<object> $classMetadata */
    protected function countValuesOffCurrentSalt(
        Connection $connection,
        AbstractPlatform $platform,
        OrmClassMetadata $classMetadata,
        string $fieldName,
        AbstractEncryptor $encryptor,
    ): int {
        $quotedColumn = $platform->quoteIdentifier($classMetadata->getColumnName($fieldName));

        $sql = \sprintf(
            'SELECT COUNT(*) FROM %s WHERE %s IS NOT NULL AND %s NOT LIKE ? ESCAPE %s',
            $platform->quoteIdentifier($this->getTableNameForField($classMetadata, $fieldName)),
            $quotedColumn,
            $quotedColumn,
            $platform->quoteStringLiteral(static::LIKE_ESCAPE_CHARACTER),
        );
        $parameters = [$this->escapeLikePattern($encryptor->getCurrentEnvelopePrefix()) . '%'];

        /* under SINGLE_TABLE the siblings share the column but were never loaded, so only the rows the walk could see are counted */
        if (true === $classMetadata->isInheritanceTypeSingleTable() && null !== $classMetadata->discriminatorColumn) {
            $discriminatorValues = $this->getDiscriminatorValues($classMetadata);

            $sql .= \sprintf(
                ' AND %s IN (%s)',
                $platform->quoteIdentifier($classMetadata->discriminatorColumn->name),
                \implode(', ', \array_fill(0, \count($discriminatorValues), '?')),
            );
            $parameters = [...$parameters, ...$discriminatorValues];
        }

        $count = $connection->fetchOne($sql, $parameters);

        if (false === \is_numeric($count)) {
            throw new Exception('verification count query returned non-numeric result');
        }

        return (int)$count;
    }

    /**
     * @phpstan-param OrmClassMetadata<object> $classMetadata
     * @return list<string> the discriminator values of the class and of every subclass, which is what `SELECT e FROM Class` loads
     */
    protected function getDiscriminatorValues(OrmClassMetadata $classMetadata): array
    {
        $classNames = [$classMetadata->name, ...$classMetadata->subClasses];

        return \array_map(
            'strval',
            \array_keys(
                \array_filter(
                    $classMetadata->discriminatorMap,
                    static fn(string $className): bool => \in_array($className, $classNames, true),
                ),
            ),
        );
    }

    /** @phpstan-param OrmClassMetadata<object> $classMetadata */
    protected function getTableNameForField(OrmClassMetadata $classMetadata, string $fieldName): string
    {
        /* under JOINED inheritance an inherited column lives in the declaring class' own table, never in the one this metadata names */
        $inheritedClassName = $classMetadata->fieldMappings[$fieldName]->inherited ?? null;

        if (null === $inheritedClassName) {
            return $classMetadata->getTableName();
        }

        return $this->getManager()->getClassMetadata($inheritedClassName)->getTableName();
    }

    protected function escapeLikePattern(string $value): string
    {
        return \str_replace(
            [static::LIKE_ESCAPE_CHARACTER, '%', '_'],
            [
                static::LIKE_ESCAPE_CHARACTER . static::LIKE_ESCAPE_CHARACTER,
                static::LIKE_ESCAPE_CHARACTER . '%',
                static::LIKE_ESCAPE_CHARACTER . '_',
            ],
            $value,
        );
    }
}
