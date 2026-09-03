<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\ParameterNameRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<ParameterNameRule>
 */
final class ParameterNameRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/ParameterName/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['name `$config` is an abbreviation, write the full word', FixtureLine::getLine($fixture, 'run(array $config')],
                ['name `$value1` is numbered, give each variable a descriptive name', FixtureLine::getLine($fixture, 'run(array $config')],
                ['name `$e` is an abbreviation, write the full word', FixtureLine::getLine($fixture, 'catch (Throwable $e)')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/ParameterName/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new ParameterNameRule(['config', 'e'], ['sha1']);
    }
}
