<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\CommentMarker;

/**
 * TODO: document the class
 */
class Violation
{
    // FIXME the return value
    public function run(): string
    {
        return 'value'; /* XXX */
    }
}
