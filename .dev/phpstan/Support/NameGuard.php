<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Support;

class NameGuard
{
    /**
     * @param list<string> $abbreviationList
     * @param list<string> $numberedNameAllowList
     */
    public function __construct(
        protected readonly array $abbreviationList,
        protected readonly array $numberedNameAllowList,
    ) {}

    /** @return array{0: string, 1: string}|null the identifier suffix and the message */
    public function getViolation(string $name): ?array
    {
        if (true === \in_array($name, $this->abbreviationList, true)) {
            return ['abbreviation', \sprintf('name `$%s` is an abbreviation, write the full word', $name)];
        }

        if (
            1 === \preg_match('/[a-z]\d+$/', $name)
            && false === \in_array($name, $this->numberedNameAllowList, true)
        ) {
            return ['numberedName', \sprintf('name `$%s` is numbered, give each variable a descriptive name', $name)];
        }

        return null;
    }
}
