<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Stmt\ClassMethod;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<ClassMethod> */
class AccessorNameRule implements Rule
{
    public function getNodeType(): string
    {
        return ClassMethod::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $methodName = $node->name->toString();

        if (false === $node->isPublic() || 1 !== \preg_match('/^is[A-Z0-9]/', $methodName)) {
            return [];
        }

        $classReflection = $scope->getClassReflection();

        if (null !== $classReflection) {
            foreach ([...$classReflection->getParents(), ...$classReflection->getInterfaces()] as $ancestorReflection) {
                if (true === $ancestorReflection->hasNativeMethod($methodName)) {
                    return [];
                }
            }
        }

        $suffix = \substr($methodName, 2);

        return [
            RuleErrorBuilder::message(
                \sprintf(
                    'public method `%s()` must not use the `is` prefix, name it `get%s()` or `has%s()`',
                    $methodName,
                    $suffix,
                    $suffix,
                ),
            )
                ->identifier('precisionSoft.isAccessor')
                ->build(),
        ];
    }
}
