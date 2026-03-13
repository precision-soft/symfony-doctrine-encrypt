<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Service;

use Doctrine\ORM\EntityManagerInterface;
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

        return isset($encryptionFields[$field]);
    }

    /**
     * Returns true if the field is mapped with an encrypted Doctrine type.
     *
     * @param object|string $entity object instance or class string
     */
    public function isEncrypted(
        object|string $entity,
        string $field,
        ?string $managerName = null,
    ): bool {
        $class = \is_object($entity) ? $entity::class : $entity;

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
     * Encrypts $value using the encryptor configured for the given field and sets it as a query parameter.
     * Requires the field to use a fixed (deterministic) encryptor such as AES256FixedType,
     * otherwise the encrypted value will differ on every call and the WHERE will never match.
     */
    public function setEncryptedParameter(
        QueryBuilder $queryBuilder,
        string $paramName,
        string $class,
        string $field,
        string $value,
        ?string $managerName = null,
    ): void {
        $encryptor = $this->getEncryptor($class, $field, $managerName);

        $queryBuilder->setParameter($paramName, $encryptor->encrypt($value));
    }

    /**
     * Returns true if the raw database value for the given field on the given entity is currently encrypted.
     * Performs an extra DBAL query to read the raw column value.
     */
    public function isValueEncrypted(
        object $entity,
        string $field,
        ?string $managerName = null,
    ): bool {
        /** @var EntityManagerInterface $entityManager */
        $entityManager = $this->managerRegistry->getManager($managerName);

        /** @var \Doctrine\ORM\Mapping\ClassMetadata $classMetadata */
        $classMetadata = $entityManager->getClassMetadata($entity::class);

        $columnName = $classMetadata->getColumnName($field);
        $tableName = $classMetadata->getTableName();
        $identifiers = $classMetadata->getIdentifierValues($entity);

        $queryBuilder = $entityManager->getConnection()->createQueryBuilder()
            ->select($columnName)
            ->from($tableName);

        foreach ($identifiers as $idField => $idValue) {
            $idColumn = $classMetadata->getColumnName($idField);
            $queryBuilder
                ->andWhere($idColumn . ' = :' . $idField)
                ->setParameter($idField, $idValue);
        }

        $rawValue = $queryBuilder->executeQuery()->fetchOne();

        return \str_starts_with((string) $rawValue, AbstractEncryptor::ENCRYPTION_MARKER);
    }

    /** @return EntityMetadataDto[] */
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
    private function getEncryptedFields(
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
    private function getFieldsForClassMetadata(ClassMetadata $classMetadata): array
    {
        $encryptedTypes = $this->encryptorFactory->getTypeNames();
        $encryptionFields = [];

        foreach ($classMetadata->getFieldNames() as $fieldName) {
            $type = $classMetadata->getTypeOfField($fieldName);

            if (true === \in_array($type, $encryptedTypes, true)) {
                $encryptionFields[$fieldName] = $type;
            }
        }

        return $encryptionFields;
    }
}
