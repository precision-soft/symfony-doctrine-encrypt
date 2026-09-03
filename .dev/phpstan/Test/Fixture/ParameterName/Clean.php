<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\ParameterName;

use Throwable;

class Clean
{
    /** @param array<string, string> $configuration */
    public function run(array $configuration, string $firstValue, string $sha1): string
    {
        try {
            $closure = static fn(string $secondValue): string => $secondValue . $sha1;

            return $closure($configuration['key'] ?? $firstValue);
        } catch (Throwable $throwable) {
            return $throwable->getMessage();
        }
    }
}
