<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\NegationRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<NegationRule>
 */
final class NegationRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/Negation/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['negation operator is forbidden, write an explicit comparison instead', FixtureLine::getLine($fixture, 'if (!$flag)')],
                ['negation operator is forbidden, write an explicit comparison instead', FixtureLine::getLine($fixture, 'return !\\is_string')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/Negation/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new NegationRule();
    }
}
