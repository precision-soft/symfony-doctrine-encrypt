<?php

declare(strict_types=1);

namespace PrecisionSoft\Dev\PhpStan\Test\Fixture\MessageCase;

use Psr\Log\LoggerInterface;
use RuntimeException;

class Clean
{
    public function __construct(protected LoggerInterface $logger)
    {
    }

    public function run(string $name): never
    {
        $this->logger->error('unable to load the fixture `MockDto`');
        $this->logger->log('warning', \sprintf('fixture `%s` is missing, SQL and JSON are fine', $name));
        $this->logger->info("loading {$name} now with onFlush");
        $this->logger->debug($name);
        $this->logger->notice(message: 'named argument stays lowercase');

        throw new RuntimeException(\sprintf('fixture %s is broken: %s', $name, $name), 0);
    }
}
