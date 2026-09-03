<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\VariableName;

class Clean
{
    /** @param array<string, string> $configuration */
    public function run(array $configuration): string
    {
        $configDto = $configuration;
        $firstResult = 'first';
        $ciphertextV1 = 'v1';
        $sha1 = \sha1($firstResult);
        $utf8 = 'utf8';
        $callback = static fn(): string => $configDto['key'] ?? $firstResult;

        for ($index = 0; $index < 1; ++$index) {
            $firstResult = $callback() . $ciphertextV1 . $sha1 . $utf8 . $this->run([]);
        }

        return $firstResult;
    }
}
