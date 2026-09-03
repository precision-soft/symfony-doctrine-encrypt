<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\VariableNameRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<VariableNameRule>
 */
final class VariableNameRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/VariableName/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['name `$config` is an abbreviation, write the full word', FixtureLine::getLine($fixture, '$config = $configuration')],
                ['name `$result1` is numbered, give each variable a descriptive name', FixtureLine::getLine($fixture, '$result1 = \'first\'')],
                ['name `$config` is an abbreviation, write the full word', FixtureLine::getLine($fixture, '$callback = static fn')],
                ['name `$result1` is numbered, give each variable a descriptive name', FixtureLine::getLine($fixture, '$callback = static fn')],
                ['name `$i` is an abbreviation, write the full word', FixtureLine::getLine($fixture, 'for ($i = 0')],
                ['name `$i` is an abbreviation, write the full word', FixtureLine::getLine($fixture, 'for ($i = 0')],
                ['name `$i` is an abbreviation, write the full word', FixtureLine::getLine($fixture, 'for ($i = 0')],
                ['name `$result1` is numbered, give each variable a descriptive name', FixtureLine::getLine($fixture, '$result1 = $callback()')],
                ['name `$result1` is numbered, give each variable a descriptive name', FixtureLine::getLine($fixture, 'return $result1')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/VariableName/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new VariableNameRule(['config', 'i'], ['sha1', 'utf8']);
    }
}
