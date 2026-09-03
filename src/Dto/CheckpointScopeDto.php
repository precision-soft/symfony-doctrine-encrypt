<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Dto;

readonly class CheckpointScopeDto
{
    public function __construct(
        protected string $command,
        protected ?string $manager,
        protected string $saltVersion,
    ) {}

    public function getCommand(): string
    {
        return $this->command;
    }

    public function getManager(): ?string
    {
        return $this->manager;
    }

    public function getSaltVersion(): string
    {
        return $this->saltVersion;
    }

    /** @return array{command: string, manager: string|null, saltVersion: string} */
    public function toArray(): array
    {
        return [
            'command' => $this->command,
            'manager' => $this->manager,
            'saltVersion' => $this->saltVersion,
        ];
    }
}
