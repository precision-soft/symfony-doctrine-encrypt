<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\MemberOrderRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<MemberOrderRule>
 */
final class MemberOrderRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/MemberOrder/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['class member `describe` is out of order: abstract method must come before constructor', FixtureLine::getLine($fixture, 'abstract protected function describe()')],
                ['class member `create` is out of order: public static method must come before public method', FixtureLine::getLine($fixture, 'public static function create()')],
                ['class member `LABEL` is out of order: protected constant must come before public method', FixtureLine::getLine($fixture, 'protected const LABEL')],
                ['class member `getName` is out of order: public method must come before protected method', FixtureLine::getLine($fixture, 'public function getName()')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/MemberOrder/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new MemberOrderRule();
    }
}
