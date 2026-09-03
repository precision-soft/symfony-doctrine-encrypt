<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\StaticReferenceRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<StaticReferenceRule>
 */
final class StaticReferenceRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/StaticReference/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['`self::` must be `static::` where late static binding is legal', FixtureLine::getLine($fixture, 'new self()')],
                ['`self::` must be `static::` where late static binding is legal', FixtureLine::getLine($fixture, 'self::$counter++')],
                ['`self::` must be `static::` where late static binding is legal', FixtureLine::getLine($fixture, 'self::NAME . self::describe()')],
                ['`self::` must be `static::` where late static binding is legal', FixtureLine::getLine($fixture, 'self::NAME . self::describe()')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/StaticReference/Clean.php'], []);
        $this->analyse([__DIR__ . '/Fixture/StaticReference/Marker.php'], []);
        $this->analyse([__DIR__ . '/Fixture/StaticReference/Suit.php'], []);
        $this->analyse([__DIR__ . '/Fixture/StaticReference/Sealed.php'], []);
    }

    protected function getRule(): Rule
    {
        return new StaticReferenceRule();
    }
}
