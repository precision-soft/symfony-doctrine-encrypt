<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Tools\DsnParser;
use Doctrine\DBAL\Types\Type;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\ClassMetadata;
use Doctrine\ORM\Mapping\Driver\AttributeDriver;
use Doctrine\ORM\Tools\SchemaTool;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\BigintEncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedChild;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedParent;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity\EncryptedSubject;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\Exception\FixtureException;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

/**
 * `DATABASE_URL_*` is exported whether or not the `db` profile runs, so a test must attempt the connection and skip on the exception rather than branch on the variable.
 *
 * @internal
 */
final class IntegrationDatabase
{
    public const SALT_V1 = 'integration-salt-v1-abcdefghijklmn';
    public const SALT_V2 = 'integration-salt-v2-opqrstuvwxyz01';

    /** @var list<class-string> */
    public const ENTITY_CLASSES = [EncryptedSubject::class, BigintEncryptedSubject::class, EncryptedParent::class, EncryptedChild::class];

    /** @return iterable<string, array{string}> */
    public static function dataProviderEngine(): iterable
    {
        yield 'mysql' => ['DATABASE_URL_MYSQL'];
        yield 'mariadb' => ['DATABASE_URL_MARIADB'];
    }

    /**
     * @throws SkipIntegrationException when the database is unreachable, so the caller can skip rather than fail
     */
    public static function createConnection(string $environmentVariable): Connection
    {
        $databaseUrl = \getenv($environmentVariable);

        if (false === $databaseUrl || '' === $databaseUrl) {
            throw new SkipIntegrationException(\sprintf(
                '`%s` is not set — this suite expects the dev container from `.dev/docker/`',
                $environmentVariable,
            ));
        }

        /* the scheme map is required — a bare `mysql://` DSN resolves to no DBAL driver — and parsing stays outside the try below, because only an unreachable server may become a skip */
        $connection = DriverManager::getConnection(
            (new DsnParser(['mysql' => 'pdo_mysql', 'mariadb' => 'pdo_mysql']))->parse($databaseUrl),
        );

        try {
            $connection->executeQuery('SELECT 1');
        } catch (DbalException $dbalException) {
            throw new SkipIntegrationException(\sprintf(
                'cannot reach the database behind `%s` (%s) — start it with `./dc --profile db up -d`',
                $environmentVariable,
                $dbalException->getMessage(),
            ));
        }

        return $connection;
    }

    /* deliberately not `ORMSetup::createAttributeMetadataConfiguration()`, which hard-requires `symfony/cache` — a dependency this bundle does not have */
    public static function createEntityManager(Connection $connection): EntityManagerInterface
    {
        $configuration = new Configuration();
        $configuration->setMetadataDriverImpl(new AttributeDriver([__DIR__ . '/Entity']));
        $configuration->setProxyDir(\sys_get_temp_dir() . '/precision-soft-doctrine-encrypt-proxies');
        $configuration->setProxyNamespace('PrecisionSoftDoctrineEncryptTestProxies');
        $configuration->setAutoGenerateProxyClasses(true);

        return new EntityManager($connection, $configuration);
    }

    /* the `hasType` guard is not redundant: Doctrine's type registry is global, so a second `addType()` for the same name throws */
    public static function registerTypes(EncryptorInterface $randomEncryptor, EncryptorInterface $deterministicEncryptor): void
    {
        if ('encryptedAes256' !== Aes256Type::getFullName() || 'encryptedAes256fixed' !== Aes256FixedType::getFullName()) {
            throw new FixtureException('the encrypted type names drifted from the fixture mapping');
        }

        foreach ([Aes256Type::class => $randomEncryptor, Aes256FixedType::class => $deterministicEncryptor] as $typeClass => $encryptor) {
            /** @var class-string<AbstractType> $typeClass */
            $typeName = $typeClass::getFullName();

            if (false === Type::hasType($typeName)) {
                Type::addType($typeName, $typeClass);
            }

            $type = Type::getType($typeName);

            if (false === ($type instanceof AbstractType)) {
                throw new FixtureException(\sprintf('`%s` is not an encrypted type', $typeName));
            }

            $type->setEncryptor($encryptor);
        }
    }

    public static function createSchema(EntityManagerInterface $entityManager): void
    {
        $schemaTool = new SchemaTool($entityManager);
        $classMetadata = static::getClassMetadata($entityManager);

        $schemaTool->dropSchema($classMetadata);
        $schemaTool->createSchema($classMetadata);
    }

    public static function dropSchema(EntityManagerInterface $entityManager): void
    {
        (new SchemaTool($entityManager))->dropSchema(static::getClassMetadata($entityManager));
    }

    /** @return list<ClassMetadata<object>> */
    private static function getClassMetadata(EntityManagerInterface $entityManager): array
    {
        return \array_map(
            static fn(string $className): ClassMetadata => $entityManager->getClassMetadata($className),
            static::ENTITY_CLASSES,
        );
    }
}
