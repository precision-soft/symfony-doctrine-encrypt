<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\CommentMarker;

/**
 * a todo list is not a marker, and neither is TODOS or a xxxTODO word
 */
class Clean
{
    public function run(): string
    {
        return 'TODO inside a string is not a comment';
    }
}
