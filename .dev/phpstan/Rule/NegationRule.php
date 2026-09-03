<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr\BooleanNot;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<BooleanNot> */
class NegationRule implements Rule
{
    public function getNodeType(): string
    {
        return BooleanNot::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        return [
            RuleErrorBuilder::message('negation operator is forbidden, write an explicit comparison instead')
                ->identifier('precisionSoft.negation')
                ->build(),
        ];
    }
}
