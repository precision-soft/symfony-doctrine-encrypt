<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Tools\DsnParser;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use PrecisionSoft\Doctrine\Encrypt\Example\Entity\User;

/**
 * `DATABASE_URL_*` is exported whether or not the `db` profile runs, so the connection is attempted and the skip comes from the exception.
 *
 * @internal
 */
final class CustomerDatabase
{
    public const SALT_V1 = 'customer-directory-salt-v1-abcdefghijklmnop';
    public const SALT_V2 = 'customer-directory-salt-v2-qrstuvwxyz012345';

    /** @return iterable<string, array{string}> */
    public static function dataProviderEngine(): iterable
    {
        yield 'mysql' => ['DATABASE_URL_MYSQL'];
        yield 'mariadb' => ['DATABASE_URL_MARIADB'];
    }

    /** @throws SkipException when the engine is not there */
    public static function getDatabaseUrl(string $environmentVariable): string
    {
        $databaseUrl = \getenv($environmentVariable);

        if (false === \is_string($databaseUrl) || '' === $databaseUrl) {
            throw new SkipException(\sprintf('`%s` is not set - this suite expects the dev container', $environmentVariable));
        }

        $connection = DriverManager::getConnection(
            (new DsnParser(['mysql' => 'pdo_mysql', 'mariadb' => 'pdo_mysql']))->parse($databaseUrl),
        );

        try {
            $connection->executeQuery('SELECT 1');
        } catch (DbalException $dbalException) {
            throw new SkipException(\sprintf(
                'cannot reach the database behind `%s` (%s) - start it with `./dc --profile db up -d`',
                $environmentVariable,
                $dbalException->getMessage(),
            ));
        } finally {
            $connection->close();
        }

        return $databaseUrl;
    }

    public static function createSchema(EntityManagerInterface $entityManager): void
    {
        $schemaTool = new SchemaTool($entityManager);
        $classMetadata = [$entityManager->getClassMetadata(User::class)];

        $schemaTool->dropSchema($classMetadata);
        $schemaTool->createSchema($classMetadata);
    }

    public static function dropSchema(EntityManagerInterface $entityManager): void
    {
        (new SchemaTool($entityManager))->dropSchema([$entityManager->getClassMetadata(User::class)]);
    }

    /** @return array<string, mixed> the row as stored, ciphertext included */
    public static function fetchStoredRow(Connection $connection, int $id): array
    {
        $row = $connection->fetchAssociative('SELECT id, displayName, email, phone, address FROM customer_user WHERE id = ?', [$id]);

        return true === \is_array($row) ? $row : [];
    }
}
