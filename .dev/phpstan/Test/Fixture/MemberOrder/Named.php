<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\MemberOrder;

trait Named
{
    public function getName(): string
    {
        return 'name';
    }
}
