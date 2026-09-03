<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassConst;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\EnumCase;
use PhpParser\Node\Stmt\Property;
use PhpParser\Node\Stmt\TraitUse;
use PHPStan\Analyser\Scope;
use PHPStan\Node\InClassNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<InClassNode> */
class MemberOrderRule implements Rule
{
    /** @var array<int, string> */
    protected const RANK_LABEL_LIST = [
        0 => 'trait use',
        1 => 'enum case',
        2 => 'public constant',
        3 => 'protected constant',
        4 => 'private constant',
        5 => 'public static property',
        6 => 'protected static property',
        7 => 'private static property',
        8 => 'public property',
        9 => 'protected property',
        10 => 'private property',
        11 => 'abstract method',
        12 => 'constructor',
        13 => 'magic method',
        14 => 'public static method',
        15 => 'protected static method',
        16 => 'private static method',
        17 => 'public method',
        18 => 'protected method',
        19 => 'private method',
    ];

    public function getNodeType(): string
    {
        return InClassNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $errorList = [];
        $previousRank = 0;

        foreach ($node->getOriginalNode()->stmts as $stmt) {
            $rank = $this->getRank($stmt);

            if (null === $rank) {
                continue;
            }

            if ($rank < $previousRank) {
                $errorList[] = RuleErrorBuilder::message(
                    \sprintf(
                        'class member `%s` is out of order: %s must come before %s',
                        $this->getMemberName($stmt),
                        static::RANK_LABEL_LIST[$rank],
                        static::RANK_LABEL_LIST[$previousRank],
                    ),
                )
                    ->identifier('precisionSoft.memberOrder')
                    ->line($stmt->getStartLine())
                    ->build();

                continue;
            }

            $previousRank = $rank;
        }

        return $errorList;
    }

    protected function getRank(Stmt $stmt): ?int
    {
        if (true === $stmt instanceof TraitUse) {
            return 0;
        }

        if (true === $stmt instanceof EnumCase) {
            return 1;
        }

        if (true === $stmt instanceof ClassConst) {
            return 2 + $this->getVisibilityOffset($stmt->isPublic(), $stmt->isProtected());
        }

        if (true === $stmt instanceof Property) {
            return (true === $stmt->isStatic() ? 5 : 8) + $this->getVisibilityOffset($stmt->isPublic(), $stmt->isProtected());
        }

        if (false === $stmt instanceof ClassMethod) {
            return null;
        }

        if (true === $stmt->isAbstract()) {
            return 11;
        }

        $methodName = $stmt->name->toLowerString();

        if ('__construct' === $methodName) {
            return 12;
        }

        if (true === \str_starts_with($methodName, '__')) {
            return 13;
        }

        $visibilityOffset = $this->getVisibilityOffset($stmt->isPublic(), $stmt->isProtected());

        return (true === $stmt->isStatic() ? 14 : 17) + $visibilityOffset;
    }

    protected function getVisibilityOffset(bool $isPublic, bool $isProtected): int
    {
        if (true === $isPublic) {
            return 0;
        }

        return true === $isProtected ? 1 : 2;
    }

    protected function getMemberName(Stmt $stmt): string
    {
        if (true === $stmt instanceof TraitUse) {
            return $stmt->traits[0]->toString();
        }

        if (true === $stmt instanceof EnumCase || true === $stmt instanceof ClassMethod) {
            return $stmt->name->toString();
        }

        if (true === $stmt instanceof ClassConst) {
            return $stmt->consts[0]->name->toString();
        }

        if (true === $stmt instanceof Property) {
            return '$' . $stmt->props[0]->name->toString();
        }

        return $stmt->getType();
    }
}
