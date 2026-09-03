<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\MessageCaseRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<MessageCaseRule>
 */
final class MessageCaseRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/MessageCase/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['message must be lowercase, found `Unable`', FixtureLine::getLine($fixture, 'error(\'Unable')],
                ['message must be lowercase, found `Fixture`', FixtureLine::getLine($fixture, '\'Fixture `%s` is missing\'')],
                ['message must be lowercase, found `Loading`', FixtureLine::getLine($fixture, 'info("Loading')],
                ['message must be lowercase, found `Fixture`', FixtureLine::getLine($fixture, '\'Fixture %s is broken\'')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/MessageCase/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new MessageCaseRule(static::createReflectionProvider());
    }
}
