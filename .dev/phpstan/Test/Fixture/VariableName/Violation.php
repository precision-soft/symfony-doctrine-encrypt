<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\VariableName;

class Violation
{
    /** @param array<string, string> $configuration */
    public function run(array $configuration): string
    {
        $config = $configuration;
        $result1 = 'first';
        $callback = static fn(): string => $config['key'] ?? $result1;

        for ($i = 0; $i < 1; ++$i) {
            $result1 = $callback();
        }

        return $result1;
    }
}
