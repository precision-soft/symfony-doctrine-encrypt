<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\StaticReference;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD)]
class Marker
{
    public function __construct(public string $value = self::class)
    {
    }
}
