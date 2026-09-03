<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Param;
use PhpParser\Node\Stmt\Catch_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PrecisionSoft\Dev\PhpStan\Support\NameGuard;

/** @implements Rule<Node> */
class ParameterNameRule implements Rule
{
    protected readonly NameGuard $nameGuard;

    /**
     * @param list<string> $abbreviationList
     * @param list<string> $numberedNameAllowList
     */
    public function __construct(array $abbreviationList, array $numberedNameAllowList)
    {
        $this->nameGuard = new NameGuard($abbreviationList, $numberedNameAllowList);
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (false === $node instanceof Param && false === $node instanceof Catch_) {
            return [];
        }

        $variable = $node->var;

        if (false === $variable instanceof Variable || false === \is_string($variable->name)) {
            return [];
        }

        $violation = $this->nameGuard->getViolation($variable->name);

        if (null === $violation) {
            return [];
        }

        [$identifier, $message] = $violation;

        return [
            RuleErrorBuilder::message($message)
                ->identifier('precisionSoft.' . $identifier)
                ->line($variable->getStartLine())
                ->build(),
        ];
    }
}
