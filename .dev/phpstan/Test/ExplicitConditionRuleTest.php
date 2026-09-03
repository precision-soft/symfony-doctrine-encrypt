<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\ExplicitConditionRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<ExplicitConditionRule>
 */
final class ExplicitConditionRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/ExplicitCondition/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['condition must be an explicit comparison, found `Expr_Variable`', FixtureLine::getLine($fixture, 'if ($flag)')],
                ['condition must be an explicit comparison, found `Expr_Isset`', FixtureLine::getLine($fixture, 'if (isset($items[0]))')],
                ['condition must be an explicit comparison, found `Expr_FuncCall`', FixtureLine::getLine($fixture, 'while (\\count($items))')],
                ['condition must be an explicit comparison, found `Expr_Instanceof`', FixtureLine::getLine($fixture, 'if ($object instanceof ArrayObject)')],
                ['condition must be an explicit comparison, found `Expr_Variable`', FixtureLine::getLine($fixture, 'if (true === $flag && $value)')],
                ['the `?:` operator is forbidden, write the condition and both branches explicitly', FixtureLine::getLine($fixture, '$value ?: ')],
                ['condition must be an explicit comparison, found `Expr_Variable`', FixtureLine::getLine($fixture, 'return $flag ? $result')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/ExplicitCondition/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new ExplicitConditionRule();
    }
}
