<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\SqlKeywordCase;

class Clean
{
    /** @return list<string> */
    public function run(string $table): array
    {
        return [
            'SELECT id, created_at AS createdAt FROM product WHERE price > 1 ORDER BY id DESC',
            'SELECT COUNT(*) AS total FROM product WHERE name = :name AND `ORDER` = 1',
            "INSERT INTO {$table} (name) VALUES ('UPPER CASE VALUE')",
            'SELECT p FROM App\Entity\Product p WHERE p.id = :id AND p.createdAt IS NOT NULL',
            'SELECT GET_LOCK(?, ?) AS lockAcquired',
            'SELECT JSON_SEARCH(payload, \'one\', :needle), DATE_FORMAT(created_at, \'%Y\') FROM product WHERE id = :id',
            'select this is not sql',
            'create the database schema for the corresponding auditor',
            'update the database schema, then compare the index list with the view',
        ];
    }
}
