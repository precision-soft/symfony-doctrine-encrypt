<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\BinaryOp;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Expr\BinaryOp\Identical;
use PhpParser\Node\Expr\BinaryOp\NotEqual;
use PhpParser\Node\Expr\BinaryOp\NotIdentical;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\UnaryMinus;
use PhpParser\Node\Expr\UnaryPlus;
use PhpParser\Node\Scalar;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<BinaryOp> */
class YodaComparisonRule implements Rule
{
    public function getNodeType(): string
    {
        return BinaryOp::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (
            false === $node instanceof Identical
            && false === $node instanceof NotIdentical
            && false === $node instanceof Equal
            && false === $node instanceof NotEqual
        ) {
            return [];
        }

        if (false === $this->isConstantLike($node->right) || true === $this->isConstantLike($node->left)) {
            return [];
        }

        return [
            RuleErrorBuilder::message('write the constant on the left side of the comparison (yoda style)')
                ->identifier('precisionSoft.yoda')
                ->build(),
        ];
    }

    protected function isConstantLike(Expr $expr): bool
    {
        if (true === $expr instanceof UnaryMinus || true === $expr instanceof UnaryPlus) {
            return $this->isConstantLike($expr->expr);
        }

        if (true === $expr instanceof Scalar) {
            return false === $expr instanceof InterpolatedString;
        }

        return true === $expr instanceof ConstFetch
            || true === $expr instanceof ClassConstFetch
            || true === $expr instanceof Array_;
    }
}
