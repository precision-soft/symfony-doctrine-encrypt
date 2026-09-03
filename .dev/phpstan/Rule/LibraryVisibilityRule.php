<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Stmt\Class_;
use PHPStan\Analyser\Scope;
use PHPStan\Node\InClassNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PrecisionSoft\Dev\PhpStan\Support\PathGuard;

/** @implements Rule<InClassNode> */
class LibraryVisibilityRule implements Rule
{
    protected readonly PathGuard $pathGuard;

    /** @param list<string> $libraryPathList */
    public function __construct(array $libraryPathList)
    {
        $this->pathGuard = new PathGuard($libraryPathList);
    }

    public function getNodeType(): string
    {
        return InClassNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (false === $this->pathGuard->containsFile($scope->getFile())) {
            return [];
        }

        $classLike = $node->getOriginalNode();

        if (null === $classLike->name) {
            return [];
        }

        $errorList = [];

        if (true === $classLike instanceof Class_ && true === $classLike->isFinal()) {
            $errorList[] = RuleErrorBuilder::message(
                \sprintf('library class `%s` must not be final', $classLike->name->toString()),
            )
                ->identifier('precisionSoft.finalClass')
                ->line($classLike->getStartLine())
                ->build();
        }

        foreach ($classLike->getMethods() as $classMethod) {
            if (true === $classMethod->isFinal()) {
                $errorList[] = RuleErrorBuilder::message(
                    \sprintf('library method `%s()` must not be final', $classMethod->name->toString()),
                )
                    ->identifier('precisionSoft.finalMethod')
                    ->line($classMethod->getStartLine())
                    ->build();
            }

            if (true === $classMethod->isPrivate()) {
                $errorList[] = RuleErrorBuilder::message(
                    \sprintf('library method `%s()` must be protected, not private', $classMethod->name->toString()),
                )
                    ->identifier('precisionSoft.privateMethod')
                    ->line($classMethod->getStartLine())
                    ->build();
            }
        }

        return $errorList;
    }
}
