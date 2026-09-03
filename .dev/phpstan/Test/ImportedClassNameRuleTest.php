<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Test;

use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PrecisionSoft\Dev\PhpStan\Rule\ImportedClassNameRule;
use PrecisionSoft\Dev\PhpStan\Test\Utility\FixtureLine;

/**
 * @internal
 * @extends RuleTestCase<ImportedClassNameRule>
 */
final class ImportedClassNameRuleTest extends RuleTestCase
{
    public function testViolation(): void
    {
        $fixture = __DIR__ . '/Fixture/ImportedClassName/Violation.php';

        $this->analyse(
            [$fixture],
            [
                ['class `ReturnTypeWillChange` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, '#[\\ReturnTypeWillChange]')],
                ['class `ArrayObject` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, 'run(\\ArrayObject')],
                ['class `ArrayIterator` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, 'new \\ArrayIterator')],
                ['class `Countable` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, 'instanceof \\Countable')],
                ['class `Closure` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, '\\Closure::fromCallable')],
                ['class `Throwable` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, 'catch (\\Throwable')],
                ['class `RuntimeException` must be imported with `use` instead of being referenced inline', FixtureLine::getLine($fixture, 'new \\RuntimeException')],
            ],
        );
    }

    public function testClean(): void
    {
        $this->analyse([__DIR__ . '/Fixture/ImportedClassName/Clean.php'], []);
    }

    protected function getRule(): Rule
    {
        return new ImportedClassNameRule();
    }
}
