<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\Throw_;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<Throw_> */
class LibraryExceptionRule implements Rule
{
    public function __construct(protected readonly ReflectionProvider $reflectionProvider) {}

    public function getNodeType(): string
    {
        return Throw_::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $thrownExpr = $node->expr;

        if (false === $thrownExpr instanceof New_ || false === $thrownExpr->class instanceof Name) {
            return [];
        }

        if (true === $thrownExpr->class->isSpecialClassName()) {
            return [];
        }

        $className = $scope->resolveName($thrownExpr->class);

        if (false === $this->reflectionProvider->hasClass($className)) {
            return [];
        }

        if (false === $this->reflectionProvider->getClass($className)->isBuiltin()) {
            return [];
        }

        return [
            RuleErrorBuilder::message(
                \sprintf('built-in exception `%s` must not be thrown, use a project-specific exception', $className),
            )
                ->identifier('precisionSoft.builtinException')
                ->build(),
        ];
    }
}
