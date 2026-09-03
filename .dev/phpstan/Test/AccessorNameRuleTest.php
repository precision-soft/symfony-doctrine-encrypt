<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\AccessorNameRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<AccessorNameRule>
 */
final class AccessorNameRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/AccessorName/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['public method `isReady()` must not use the `is` prefix, name it `getReady()` or `hasReady()`', FixtureLine::getLine($fixture, 'function isReady()')],
                ['public method `is2faEnabled()` must not use the `is` prefix, name it `get2faEnabled()` or `has2faEnabled()`', FixtureLine::getLine($fixture, 'function is2faEnabled()')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/AccessorName/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new AccessorNameRule();
    }
}
