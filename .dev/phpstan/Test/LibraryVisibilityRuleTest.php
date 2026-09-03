<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\LibraryVisibilityRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<LibraryVisibilityRule>
 */
final class LibraryVisibilityRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/LibraryVisibility/Src/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['library class `Violation` must not be final', FixtureLine::getLine($fixture, 'final class Violation')],
                ['library method `run()` must not be final', FixtureLine::getLine($fixture, 'final public function run()')],
                ['library method `describe()` must be protected, not private', FixtureLine::getLine($fixture, 'private function describe()')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/LibraryVisibility/Src/Clean.php'], []);
        $this->analyse([__DIR__ . '/Fixture/LibraryVisibility/Outside.php'], []);
    }

    protected function getRule(): Rule
    {
        return new LibraryVisibilityRule([__DIR__ . '/Fixture/LibraryVisibility/Src']);
    }
}
