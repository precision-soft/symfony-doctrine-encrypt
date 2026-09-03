<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\ParameterName;

use Throwable;

class Violation
{
    /** @param array<string, string> $config */
    public function run(array $config, string $value1): string
    {
        try {
            return $config['key'] ?? $value1;
        } catch (Throwable $e) {
            return $e->getMessage();
        }
    }
}
