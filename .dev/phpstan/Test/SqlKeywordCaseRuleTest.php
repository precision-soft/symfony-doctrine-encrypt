<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\SqlKeywordCaseRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<SqlKeywordCaseRule>
 */
final class SqlKeywordCaseRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/SqlKeywordCase/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['sql keyword `select` must be uppercase', FixtureLine::getLine($fixture, 'id from product where price')],
                ['sql keyword `from` must be uppercase', FixtureLine::getLine($fixture, 'id from product where price')],
                ['sql keyword `where` must be uppercase', FixtureLine::getLine($fixture, 'id from product where price')],
                ['sql keyword `order by` must be uppercase', FixtureLine::getLine($fixture, 'AS Total FROM PRODUCT')],
                ['sql identifier `PRODUCT` must be lowercase (only keywords and functions are uppercase)', FixtureLine::getLine($fixture, 'AS Total FROM PRODUCT')],
                ['sql keyword `set` must be uppercase', FixtureLine::getLine($fixture, '{$table} set name')],
                ['sql keyword `and` must be uppercase', FixtureLine::getLine($fixture, 'p.id = :id and p.name')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/SqlKeywordCase/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new SqlKeywordCaseRule();
    }
}
