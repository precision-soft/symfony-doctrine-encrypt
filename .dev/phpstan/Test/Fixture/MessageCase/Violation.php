<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\MessageCase;

use Psr\Log\LoggerInterface;
use RuntimeException;

class Violation
{
    public function __construct(protected LoggerInterface $logger)
    {
    }

    public function run(string $name): never
    {
        $this->logger->error('Unable to load the fixture');
        $this->logger->log('warning', \sprintf('Fixture `%s` is missing', $name));
        $this->logger->info("Loading {$name} now");

        throw new RuntimeException(\sprintf('Fixture %s is broken', $name));
    }
}
