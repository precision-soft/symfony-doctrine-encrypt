<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FileNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PhpToken;

/** @implements Rule<FileNode> */
class CommentMarkerRule implements Rule
{
    public function getNodeType(): string
    {
        return FileNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $code = \file_get_contents($scope->getFile());

        if (false === $code) {
            return [];
        }

        $errorList = [];

        foreach (PhpToken::tokenize($code) as $phpToken) {
            if (false === $phpToken->is([\T_COMMENT, \T_DOC_COMMENT])) {
                continue;
            }

            foreach (\explode("\n", $phpToken->text) as $offset => $commentLine) {
                if (1 !== \preg_match('/\b(TODO|FIXME|XXX)\b/', $commentLine, $matchList)) {
                    continue;
                }

                $errorList[] = RuleErrorBuilder::message(
                    \sprintf('comment carries a `%s` marker, track the work in the issue tracker instead', $matchList[1]),
                )
                    ->identifier('precisionSoft.todoComment')
                    ->line($phpToken->line + $offset)
                    ->build();
            }
        }

        return $errorList;
    }
}
