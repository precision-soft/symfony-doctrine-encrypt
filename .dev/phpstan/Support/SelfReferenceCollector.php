<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Support;

use PhpParser\Node;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\StaticPropertyFetch;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Param;
use PhpParser\Node\StaticVar;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;

class SelfReferenceCollector extends NodeVisitorAbstract
{
    /** @var list<int> */
    protected array $lineList = [];

    /** @return list<int> */
    public function getLineList(): array
    {
        return $this->lineList;
    }

    public function enterNode(Node $node): ?int
    {
        if (
            true === $node instanceof AttributeGroup
            || true === $node instanceof Param
            || true === $node instanceof StaticVar
        ) {
            return NodeVisitor::DONT_TRAVERSE_CHILDREN;
        }

        if (
            false === $node instanceof StaticCall
            && false === $node instanceof StaticPropertyFetch
            && false === $node instanceof ClassConstFetch
            && false === $node instanceof New_
        ) {
            return null;
        }

        if (false === $node->class instanceof Name || 'self' !== $node->class->toLowerString()) {
            return null;
        }

        if (
            true === $node instanceof ClassConstFetch
            && true === $node->name instanceof Identifier
            && 'class' === $node->name->toLowerString()
        ) {
            return null;
        }

        $this->lineList[] = $node->getStartLine();

        return null;
    }
}
