<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PrecisionSoft\Dev\PhpStan\Support\NameGuard;

/** @implements Rule<Variable> */
class VariableNameRule implements Rule
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
        return Variable::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (false === \is_string($node->name) || 'this' === $node->name) {
            return [];
        }

        $violation = $this->nameGuard->getViolation($node->name);

        if (null === $violation) {
            return [];
        }

        [$identifier, $message] = $violation;

        return [
            RuleErrorBuilder::message($message)
                ->identifier('precisionSoft.' . $identifier)
                ->build(),
        ];
    }
}
