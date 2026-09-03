<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\YodaComparisonRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<YodaComparisonRule>
 */
final class YodaComparisonRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/YodaComparison/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['write the constant on the left side of the comparison (yoda style)', FixtureLine::getLine($fixture, '$value === null')],
                ['write the constant on the left side of the comparison (yoda style)', FixtureLine::getLine($fixture, '$items == []')],
                ['write the constant on the left side of the comparison (yoda style)', FixtureLine::getLine($fixture, '$count !== -1')],
                ['write the constant on the left side of the comparison (yoda style)', FixtureLine::getLine($fixture, '$count != static::LIMIT')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/YodaComparison/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new YodaComparisonRule();
    }
}
