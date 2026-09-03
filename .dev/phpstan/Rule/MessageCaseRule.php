<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Identifier;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\Type\ObjectType;
use Throwable;

/** @implements Rule<Node> */
class MessageCaseRule implements Rule
{
    protected const LOGGER_INTERFACE = 'Psr\Log\LoggerInterface';
    /** @var list<string> */
    protected const LOGGER_METHOD_LIST = [
        'log',
        'debug',
        'info',
        'notice',
        'warning',
        'error',
        'critical',
        'alert',
        'emergency',
    ];

    public function __construct(protected readonly ReflectionProvider $reflectionProvider) {}

    public function getNodeType(): string
    {
        return Node::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $messageArg = $this->getMessageArg($node, $scope);

        if (null === $messageArg) {
            return [];
        }

        $message = $this->getLiteralText($messageArg->value);

        if (null === $message) {
            return [];
        }

        $capitalisedWord = $this->getCapitalisedWord($message);

        if (null === $capitalisedWord) {
            return [];
        }

        return [
            RuleErrorBuilder::message(\sprintf('message must be lowercase, found `%s`', $capitalisedWord))
                ->identifier('precisionSoft.messageCase')
                ->build(),
        ];
    }

    protected function getMessageArg(Node $node, Scope $scope): ?Arg
    {
        if (true === $node instanceof New_) {
            if (false === $node->class instanceof Name || true === $node->isFirstClassCallable()) {
                return null;
            }

            $className = $scope->resolveName($node->class);

            if (false === $this->reflectionProvider->hasClass($className)) {
                return null;
            }

            if (false === $this->reflectionProvider->getClass($className)->is(Throwable::class)) {
                return null;
            }

            return $this->getFirstArg($node->getArgs(), 'message');
        }

        if (false === $node instanceof MethodCall || false === $node->name instanceof Identifier) {
            return null;
        }

        if (true === $node->isFirstClassCallable()) {
            return null;
        }

        $methodName = $node->name->toLowerString();

        if (false === \in_array($methodName, static::LOGGER_METHOD_LIST, true)) {
            return null;
        }

        $loggerType = new ObjectType(static::LOGGER_INTERFACE);

        if (false === $loggerType->isSuperTypeOf($scope->getType($node->var))->yes()) {
            return null;
        }

        return $this->getFirstArg($node->getArgs(), 'message', 'log' === $methodName ? 1 : 0);
    }

    /** @param array<Arg> $argumentList */
    protected function getFirstArg(array $argumentList, string $argumentName, int $position = 0): ?Arg
    {
        $positionalIndex = 0;

        foreach ($argumentList as $argument) {
            if (null !== $argument->name) {
                if ($argumentName === $argument->name->toString()) {
                    return $argument;
                }

                continue;
            }

            if ($position === $positionalIndex) {
                return $argument;
            }

            ++$positionalIndex;
        }

        return null;
    }

    protected function getLiteralText(Expr $expr): ?string
    {
        if (true === $expr instanceof String_) {
            return $expr->value;
        }

        if (true === $expr instanceof InterpolatedString) {
            $text = '';

            foreach ($expr->parts as $part) {
                $text .= true === $part instanceof InterpolatedStringPart ? $part->value : ' ';
            }

            return $text;
        }

        if (true === $expr instanceof Concat) {
            return ($this->getLiteralText($expr->left) ?? ' ') . ($this->getLiteralText($expr->right) ?? ' ');
        }

        if (
            true === $expr instanceof FuncCall
            && true === $expr->name instanceof Name
            && 'sprintf' === $expr->name->toLowerString()
            && false === $expr->isFirstClassCallable()
        ) {
            $formatArg = $this->getFirstArg($expr->getArgs(), 'format');

            return null === $formatArg ? null : $this->getLiteralText($formatArg->value);
        }

        return null;
    }

    protected function getCapitalisedWord(string $message): ?string
    {
        $messageWithoutCode = \preg_replace('/`[^`]*`/', ' ', $message) ?? $message;

        \preg_match_all('/(?<![\w\\\\%])([A-Z][\w\\\\]*)/', $messageWithoutCode, $matchList);

        foreach ($matchList[1] as $word) {
            if (1 === \preg_match('/^[A-Z0-9_]{2,}$/', $word)) {
                continue;
            }

            return $word;
        }

        return null;
    }
}
