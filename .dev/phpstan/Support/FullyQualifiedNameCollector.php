<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Support;

use PhpParser\Node;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\NodeVisitorAbstract;
use SplObjectStorage;

class FullyQualifiedNameCollector extends NodeVisitorAbstract
{
    /** @var SplObjectStorage<Name, true> */
    protected SplObjectStorage $allowedNameStorage;
    /** @var list<array{0: string, 1: int}> */
    protected array $inlineNameList = [];

    public function __construct()
    {
        $this->allowedNameStorage = new SplObjectStorage();
    }

    /** @return list<array{0: string, 1: int}> */
    public function getInlineNameList(): array
    {
        return $this->inlineNameList;
    }

    public function enterNode(Node $node): ?Node
    {
        if (true === $node instanceof FuncCall && true === $node->name instanceof Name) {
            $this->allowedNameStorage->attach($node->name, true);
        }

        if (true === $node instanceof ConstFetch) {
            $this->allowedNameStorage->attach($node->name, true);
        }

        if (false === $node instanceof Name || true === $this->allowedNameStorage->contains($node)) {
            return null;
        }

        $originalName = $node->getAttribute('originalName');
        $name = true === $originalName instanceof Name ? $originalName : $node;

        if (true === $name instanceof FullyQualified) {
            $this->inlineNameList[] = [$name->toString(), $node->getStartLine()];
        }

        return null;
    }
}
