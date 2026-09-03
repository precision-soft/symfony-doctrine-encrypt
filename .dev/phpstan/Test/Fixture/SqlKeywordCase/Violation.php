<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\SqlKeywordCase;

class Violation
{
    /** @return list<string> */
    public function run(string $table): array
    {
        return [
            'select id from product where price > 1',
            'SELECT COUNT(*) AS Total FROM PRODUCT WHERE id = :id order by id',
            "UPDATE {$table} set name = 'x' WHERE id = ?",
            'SELECT p FROM App\Entity\Product p WHERE p.id = :id and p.name = :name',
        ];
    }
}
