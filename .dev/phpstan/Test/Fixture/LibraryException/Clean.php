<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\LibraryException;

class Clean
{
    public function run(int $value): never
    {
        try {
            if (0 === $value) {
                throw new ProjectException('value must not be zero');
            }

            throw new static();
        } catch (ProjectException $projectException) {
            throw $projectException;
        }
    }
}
