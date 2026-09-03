<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\LibraryVisibility\Src;

class Clean
{
    public function run(): string
    {
        return $this->describe();
    }

    protected function describe(): string
    {
        return 'clean';
    }
}
