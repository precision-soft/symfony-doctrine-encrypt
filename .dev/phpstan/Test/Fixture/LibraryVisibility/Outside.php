<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\LibraryVisibility;

final class Outside
{
    final public function run(): string
    {
        return $this->describe();
    }

    private function describe(): string
    {
        return 'outside the library path, so allowed';
    }
}
