<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\CommentMarkerRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<CommentMarkerRule>
 */
final class CommentMarkerRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/CommentMarker/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['comment carries a `TODO` marker, track the work in the issue tracker instead', FixtureLine::getLine($fixture, ' * TODO: document')],
                ['comment carries a `FIXME` marker, track the work in the issue tracker instead', FixtureLine::getLine($fixture, '// FIXME')],
                ['comment carries a `XXX` marker, track the work in the issue tracker instead', FixtureLine::getLine($fixture, '/* XXX */')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/CommentMarker/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new CommentMarkerRule();
    }
}
