<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\LibraryExceptionRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<LibraryExceptionRule>
 */
final class LibraryExceptionRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/LibraryException/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['built-in exception `InvalidArgumentException` must not be thrown, use a project-specific exception', FixtureLine::getLine($fixture, 'throw new InvalidArgumentException')],
                ['built-in exception `RuntimeException` must not be thrown, use a project-specific exception', FixtureLine::getLine($fixture, 'throw new \\RuntimeException')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/LibraryException/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new LibraryExceptionRule(static::createReflectionProvider());
    }
}
