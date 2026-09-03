<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FileNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PrecisionSoft\Dev\PhpStan\Support\FullyQualifiedNameCollector;

/** @implements Rule<FileNode> */
class ImportedClassNameRule implements Rule
{
    public function getNodeType(): string
    {
        return FileNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $fullyQualifiedNameCollector = new FullyQualifiedNameCollector();
        $nodeTraverser = new NodeTraverser($fullyQualifiedNameCollector);
        $nodeTraverser->traverse($node->getNodes());

        $errorList = [];

        foreach ($fullyQualifiedNameCollector->getInlineNameList() as [$name, $line]) {
            $errorList[] = RuleErrorBuilder::message(
                \sprintf('class `%s` must be imported with `use` instead of being referenced inline', $name),
            )
                ->identifier('precisionSoft.inlineClassName')
                ->line($line)
                ->build();
        }

        return $errorList;
    }
}
