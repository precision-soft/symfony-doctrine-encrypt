<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeTraverser;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PrecisionSoft\Dev\PhpStan\Support\SelfReferenceCollector;

/** @implements Rule<ClassMethod> */
class StaticReferenceRule implements Rule
{
    public function getNodeType(): string
    {
        return ClassMethod::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $classReflection = $scope->getClassReflection();

        if (null === $classReflection || null === $node->stmts) {
            return [];
        }

        if (true === $classReflection->isFinal() || true === $classReflection->isEnum()) {
            return [];
        }

        $selfReferenceCollector = new SelfReferenceCollector();
        $nodeTraverser = new NodeTraverser($selfReferenceCollector);
        $nodeTraverser->traverse($node->stmts);

        $errorList = [];

        foreach ($selfReferenceCollector->getLineList() as $line) {
            $errorList[] = RuleErrorBuilder::message('`self::` must be `static::` where late static binding is legal')
                ->identifier('precisionSoft.selfReference')
                ->line($line)
                ->build();
        }

        return $errorList;
    }
}
