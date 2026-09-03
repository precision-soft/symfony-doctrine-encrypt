<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\LibraryVisibility\Src;

final class Violation
{
    final public function run(): string
    {
        return $this->describe();
    }

    private function describe(): string
    {
        return 'violation';
    }
}
