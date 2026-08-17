<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Service;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\ClassMetadata as OrmMappingClassMetadata;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\Mapping\ClassMetadata;
use PrecisionSoft\Doctrine\Encrypt\Contract\DeterministicEncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\FieldNotEncryptedException;
use PrecisionSoft\Doctrine\Encrypt\Exception\NonDeterministicEncryptorException;

class EntityService
{
    /** @var array<string, array<string, string>> */
    protected array $encryptedFieldsCache = [];

    public function __construct(
        protected readonly ManagerRegistry $managerRegistry,
        protected readonly EncryptorFactory $encryptorFactory,
    ) {}

    public function getEncryptor(
        string $class,
        string $field,
        ?string $managerName = null,
    ): EncryptorInterface {
        $encryptionFields = $this->getEncryptedFields($class, $managerName);

        if (false === isset($encryptionFields[$field])) {
            throw new FieldNotEncryptedException(
                \sprintf('field %s::%s has no encryption defined', $class, $field),
            );
        }

        return $this->encryptorFactory->getEncryptorByType($encryptionFields[$field]);
    }

    public function hasEncryptor(
        string $class,
        string $field,
        ?string $managerName = null,
    ): bool {
        $encryptionFields = $this->getEncryptedFields($class, $managerName);

        return true === isset($encryptionFields[$field]);
    }

    public function hasEncryption(
        object|string $entity,
        string $field,
        ?string $managerName = null,
    ): bool {
        $class = true === \is_object($entity) ? $entity::class : $entity;

        return $this->hasEncryptor($class, $field, $managerName);
    }

    public function encrypt(
        string $data,
        string $class,
        string $field,
        ?string $managerName = null,
    ): string {
        $encryptor = $this->getEncryptor($class, $field, $managerName);

        return $encryptor->encrypt($data);
    }

    public function decrypt(
        string $encryptedData,
        string $class,
        string $field,
        ?string $managerName = null,
    ): string {
        $encryptor = $this->getEncryptor($class, $field, $managerName);

        return $encryptor->decrypt($encryptedData);
    }

    public function setEncryptedParameter(
        QueryBuilder $queryBuilder,
        string $parameterName,
        string $class,
        string $field,
        string $value,
        ?string $managerName = null,
    ): void {
        $encryptor = $this->getDeterministicEncryptor($class, $field, $managerName);

        $queryBuilder->setParameter($parameterName, $encryptor->encrypt($value));
    }

    /**
     * @return list<string> the ciphertext candidates, in configured salt-version order
     */
    public function setEncryptedParameterInList(
        QueryBuilder $queryBuilder,
        string $parameterName,
        string $class,
        string $field,
        string $value,
        ?string $managerName = null,
    ): array {
        $candidates = $this->getDeterministicCiphertextCandidates($class, $field, $value, $managerName);

        $queryBuilder->setParameter($parameterName, $candidates);

        return $candidates;
    }

    /**
     * @return list<string>
     */
    public function getDeterministicCiphertextCandidates(
        string $class,
        string $field,
        string $value,
        ?string $managerName = null,
    ): array {
        $encryptor = $this->getDeterministicEncryptor($class, $field, $managerName);

        if (false === ($encryptor instanceof AbstractEncryptor)) {
            throw new Exception(\sprintf(
                'encryptor %s must extend AbstractEncryptor to support multi-salt rotation lookups',
                $encryptor::class,
            ));
        }

        $candidates = [];

        foreach ($encryptor->getActiveSaltVersions() as $saltVersion) {
            $candidates[] = $encryptor->encryptWithSaltVersion($value, $saltVersion);
        }

        return $candidates;
    }

    protected function getDeterministicEncryptor(
        string $class,
        string $field,
        ?string $managerName = null,
    ): DeterministicEncryptorInterface {
        $encryptor = $this->getEncryptor($class, $field, $managerName);

        if (false === ($encryptor instanceof DeterministicEncryptorInterface)) {
            throw new NonDeterministicEncryptorException(
                \sprintf(
                    'field %s::%s uses a non-deterministic encryptor (%s); deterministic lookups require a DeterministicEncryptorInterface implementation',
                    $class,
                    $field,
                    $encryptor::class,
                ),
            );
        }

        return $encryptor;
    }

    public function hasEncryptedValue(
        object $entity,
        string $field,
        ?string $managerName = null,
    ): bool {
        /** @var EntityManagerInterface $entityManager */
        $entityManager = $this->managerRegistry->getManager($managerName);

        /** @var OrmMappingClassMetadata<object> $classMetadata */
        $classMetadata = $entityManager->getClassMetadata($entity::class);

        $identifiers = $classMetadata->getIdentifierValues($entity);

        /* getIdentifierValues() omits nulls, so an incompletely identified entity arrives as a short array and never as a null entry */
        if (\count($identifiers) !== \count($classMetadata->getIdentifierFieldNames())) {
            return false;
        }

        $connection = $entityManager->getConnection();
        $platform = $connection->getDatabasePlatform();

        $columnName = $platform->quoteSingleIdentifier($classMetadata->getColumnName($field));
        $tableName = $platform->quoteSingleIdentifier($classMetadata->getTableName());

        $queryBuilder = $connection->createQueryBuilder()
            ->select($columnName)
            ->from($tableName);

        foreach ($identifiers as $identifierField => $identifierValue) {
            $identifierColumn = $platform->quoteSingleIdentifier($classMetadata->getColumnName($identifierField));
            $queryBuilder
                ->andWhere($identifierColumn . ' = :' . $identifierField)
                ->setParameter($identifierField, $identifierValue);
        }

        $rawValue = $queryBuilder->executeQuery()->fetchOne();

        if (false === \is_string($rawValue)) {
            return false;
        }

        return true === \str_starts_with($rawValue, AbstractEncryptor::ENCRYPTION_MARKER . AbstractEncryptor::GLUE);
    }

    /**
     * @return EntityMetadataDto[]
     */
    public function getEntitiesWithEncryption(?string $managerName = null): array
    {
        $entitiesWithEncryption = [];
        $objectManager = $this->managerRegistry->getManager($managerName);

        foreach ($objectManager->getMetadataFactory()->getAllMetadata() as $classMetadata) {
            $encryptionFields = $this->getFieldsForClassMetadata($classMetadata);

            if ([] !== $encryptionFields) {
                $entitiesWithEncryption[$classMetadata->getName()] = new EntityMetadataDto($classMetadata, $encryptionFields);
            }
        }

        return $entitiesWithEncryption;
    }

    /**
     * @return array<string, string>
     */
    protected function getEncryptedFields(
        string $class,
        ?string $managerName = null,
    ): array {
        $cacheKey = ($managerName ?? '') . '|' . $class;

        if (true === isset($this->encryptedFieldsCache[$cacheKey])) {
            return $this->encryptedFieldsCache[$cacheKey];
        }

        if (false === \class_exists($class)) {
            throw new Exception(\sprintf('cannot resolve encrypted fields for unknown class `%s`', $class));
        }

        $objectManager = $this->managerRegistry->getManager($managerName);
        $classMetadata = $objectManager->getMetadataFactory()->getMetadataFor($class);

        return $this->encryptedFieldsCache[$cacheKey] = $this->getFieldsForClassMetadata($classMetadata);
    }

    /**
     * @phpstan-param ClassMetadata<object> $classMetadata
     * @return array<string, string>
     */
    protected function getFieldsForClassMetadata(ClassMetadata $classMetadata): array
    {
        $encryptedTypes = $this->encryptorFactory->getTypeNames();
        $encryptionFields = [];

        foreach ($classMetadata->getFieldNames() as $fieldName) {
            $fieldType = $classMetadata->getTypeOfField($fieldName);

            if (true === \in_array($fieldType, $encryptedTypes, true)) {
                $encryptionFields[$fieldName] = $fieldType;
            }
        }

        return $encryptionFields;
    }
}
