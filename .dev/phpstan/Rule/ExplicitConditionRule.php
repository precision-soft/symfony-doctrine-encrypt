<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\BooleanAnd;
use PhpParser\Node\Expr\BinaryOp\BooleanOr;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Expr\BinaryOp\Greater;
use PhpParser\Node\Expr\BinaryOp\GreaterOrEqual;
use PhpParser\Node\Expr\BinaryOp\Identical;
use PhpParser\Node\Expr\BinaryOp\LogicalAnd;
use PhpParser\Node\Expr\BinaryOp\LogicalOr;
use PhpParser\Node\Expr\BinaryOp\LogicalXor;
use PhpParser\Node\Expr\BinaryOp\NotEqual;
use PhpParser\Node\Expr\BinaryOp\NotIdentical;
use PhpParser\Node\Expr\BinaryOp\Smaller;
use PhpParser\Node\Expr\BinaryOp\SmallerOrEqual;
use PhpParser\Node\Expr\BooleanNot;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Stmt\Do_;
use PhpParser\Node\Stmt\ElseIf_;
use PhpParser\Node\Stmt\For_;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\While_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<Node> */
class ExplicitConditionRule implements Rule
{
    public function getNodeType(): string
    {
        return Node::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (true === $node instanceof Ternary && null === $node->if) {
            return [
                RuleErrorBuilder::message('the `?:` operator is forbidden, write the condition and both branches explicitly')
                    ->identifier('precisionSoft.elvis')
                    ->build(),
            ];
        }

        $errorList = [];

        foreach ($this->getConditionList($node) as $condition) {
            $error = $this->getConditionError($condition);

            if (null !== $error) {
                $errorList[] = $error;
            }
        }

        return $errorList;
    }

    /** @return list<Expr> */
    protected function getConditionList(Node $node): array
    {
        if (
            true === $node instanceof If_
            || true === $node instanceof ElseIf_
            || true === $node instanceof While_
            || true === $node instanceof Do_
            || true === $node instanceof Ternary
        ) {
            return [$node->cond];
        }

        if (true === $node instanceof For_) {
            return \array_values($node->cond);
        }

        if (true === $this->isLogicalOperator($node)) {
            return [$node->left, $node->right];
        }

        return [];
    }

    protected function getConditionError(Expr $condition): ?IdentifierRuleError
    {
        if (
            true === $this->isLogicalOperator($condition)
            || true === $condition instanceof BooleanNot
            || true === $this->isComparison($condition)
            || true === $this->isBooleanLiteral($condition)
        ) {
            return null;
        }

        return RuleErrorBuilder::message(
            \sprintf('condition must be an explicit comparison, found `%s`', $condition->getType()),
        )
            ->identifier('precisionSoft.implicitCondition')
            ->line($condition->getStartLine())
            ->build();
    }

    /** @phpstan-assert-if-true BooleanAnd|BooleanOr|LogicalAnd|LogicalOr|LogicalXor $node */
    protected function isLogicalOperator(Node $node): bool
    {
        return true === $node instanceof BooleanAnd
            || true === $node instanceof BooleanOr
            || true === $node instanceof LogicalAnd
            || true === $node instanceof LogicalOr
            || true === $node instanceof LogicalXor;
    }

    protected function isComparison(Expr $expr): bool
    {
        return true === $expr instanceof Identical
            || true === $expr instanceof NotIdentical
            || true === $expr instanceof Equal
            || true === $expr instanceof NotEqual
            || true === $expr instanceof Smaller
            || true === $expr instanceof SmallerOrEqual
            || true === $expr instanceof Greater
            || true === $expr instanceof GreaterOrEqual;
    }

    protected function isBooleanLiteral(Expr $expr): bool
    {
        return true === $expr instanceof ConstFetch
            && true === \in_array($expr->name->toLowerString(), ['true', 'false'], true);
    }
}
