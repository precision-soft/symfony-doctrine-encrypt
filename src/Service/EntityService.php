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
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\FieldNotEncryptedException;

class EntityService
{
    public function __construct(
        private readonly ManagerRegistry $managerRegistry,
        private readonly EncryptorFactory $encryptorFactory,
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

    /**
     * returns true when the field is mapped with an encrypted doctrine type.
     */
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

    /**
     * encrypts the given value with the encryptor configured for the field and sets it as a query parameter.
     *
     * the field must use a deterministic encryptor such as Aes256FixedType, otherwise the encrypted value changes on each call and the generated WHERE clause will never match.
     */
    public function setEncryptedParameter(
        QueryBuilder $queryBuilder,
        string $parameterName,
        string $class,
        string $field,
        string $value,
        ?string $managerName = null,
    ): void {
        $encryptor = $this->getEncryptor($class, $field, $managerName);

        $queryBuilder->setParameter($parameterName, $encryptor->encrypt($value));
    }

    /**
     * returns true when the raw database value for the given field on the given entity is currently encrypted.
     *
     * This performs an additional dbal query to read the raw column value.
     */
    public function hasEncryptedValue(
        object $entity,
        string $field,
        ?string $managerName = null,
    ): bool {
        /** @var EntityManagerInterface $entityManager */
        $entityManager = $this->managerRegistry->getManager($managerName);

        /** @var OrmMappingClassMetadata $classMetadata */
        $classMetadata = $entityManager->getClassMetadata($entity::class);

        $columnName = $classMetadata->getColumnName($field);
        $tableName = $classMetadata->getTableName();
        $identifiers = $classMetadata->getIdentifierValues($entity);

        $queryBuilder = $entityManager->getConnection()->createQueryBuilder()
            ->select($columnName)
            ->from($tableName);

        foreach ($identifiers as $identifierField => $identifierValue) {
            $identifierColumn = $classMetadata->getColumnName($identifierField);
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
    public function getEntitiesWithEncryption(?string $manager = null): array
    {
        $entities = [];
        $objectManager = $this->managerRegistry->getManager($manager);

        foreach ($objectManager->getMetadataFactory()->getAllMetadata() as $classMetadata) {
            $encryptionFields = $this->getFieldsForClassMetadata($classMetadata);

            if ([] !== $encryptionFields) {
                $entities[$classMetadata->getName()] = new EntityMetadataDto($classMetadata, $encryptionFields);
            }
        }

        return $entities;
    }

    /**
     * @return array<string, string>
     */
    protected function getEncryptedFields(
        string $class,
        ?string $managerName = null,
    ): array {
        $objectManager = $this->managerRegistry->getManager($managerName);
        $classMetadata = $objectManager->getMetadataFactory()->getMetadataFor($class);

        return $this->getFieldsForClassMetadata($classMetadata);
    }

    /**
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
