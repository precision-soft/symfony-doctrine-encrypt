<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Service;

use JsonException;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;

class CheckpointService
{
    public const FORMAT_VERSION = 1;

    protected const KEY_VERSION = 'version';
    protected const KEY_ENTITIES = 'entities';
    protected const KEY_COMPLETED = 'completed';

    protected const TEMPORARY_PREFIX = '.checkpoint-';
    protected const DIRECTORY_PERMISSIONS = 0700;

    /** @var array<string, array<string, mixed>> */
    protected array $identifierValuesByClassName = [];

    /** @var list<string> */
    protected array $completedClassNames = [];

    protected bool $loaded = false;

    public function __construct(
        protected readonly string $path = '',
    ) {}

    public function getPath(): string
    {
        return $this->path;
    }

    public function hasPath(): bool
    {
        return '' !== $this->path;
    }

    /** @return array<string, mixed>|null */
    public function getIdentifierValues(string $className): ?array
    {
        $this->load();

        return $this->identifierValuesByClassName[$className] ?? null;
    }

    /** @param array<string, mixed> $identifierValues */
    public function setIdentifierValues(string $className, array $identifierValues): static
    {
        $this->load();

        $this->identifierValuesByClassName[$className] = $identifierValues;

        $this->write();

        return $this;
    }

    /** @param string[] $classNames */
    public function markCompleted(array $classNames): static
    {
        $this->load();

        $this->completedClassNames = \array_values(
            \array_unique(\array_merge($this->completedClassNames, $classNames)),
        );

        $this->write();

        return $this;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            static::KEY_VERSION => static::FORMAT_VERSION,
            static::KEY_ENTITIES => $this->identifierValuesByClassName,
            static::KEY_COMPLETED => $this->completedClassNames,
        ];
    }

    protected function load(): void
    {
        if (true === $this->loaded) {
            return;
        }

        $this->loaded = true;

        if (false === $this->hasPath() || false === \is_file($this->path)) {
            return;
        }

        $contents = \file_get_contents($this->path);

        if (false === $contents) {
            throw new Exception(\sprintf('could not read the checkpoint `%s`', $this->path));
        }

        try {
            $decoded = \json_decode($contents, true, 512, \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new Exception(\sprintf('the checkpoint `%s` is not valid json', $this->path), 0, $jsonException);
        }

        if (
            false === \is_array($decoded)
            || static::FORMAT_VERSION !== ($decoded[static::KEY_VERSION] ?? null)
            || false === \is_array($decoded[static::KEY_ENTITIES] ?? null)
        ) {
            throw new Exception(\sprintf('the checkpoint `%s` is not a version %d checkpoint', $this->path, static::FORMAT_VERSION));
        }

        /** @var array<string, array<string, mixed>> $identifierValuesByClassName */
        $identifierValuesByClassName = $decoded[static::KEY_ENTITIES];
        $completedClassNames = $decoded[static::KEY_COMPLETED] ?? [];

        /* a completed class starts over: its stored cursor sits past the last row, so replaying it would scan nothing and report success */
        if (true === \is_array($completedClassNames)) {
            foreach ($completedClassNames as $completedClassName) {
                if (true === \is_string($completedClassName)) {
                    unset($identifierValuesByClassName[$completedClassName]);
                }
            }
        }

        $this->identifierValuesByClassName = $identifierValuesByClassName;
    }

    protected function write(): void
    {
        if (false === $this->hasPath()) {
            return;
        }

        $directory = \dirname($this->path);

        if (
            false === \is_dir($directory)
            && false === @\mkdir($directory, static::DIRECTORY_PERMISSIONS, true)
            && false === \is_dir($directory)
        ) {
            throw new Exception(\sprintf('could not create the checkpoint directory `%s`', $directory));
        }

        /* tempnam() creates the file 0600 in the destination directory, so the rename below is both atomic and never widens the permissions */
        $temporaryPath = \tempnam($directory, static::TEMPORARY_PREFIX);

        if (false === $temporaryPath) {
            throw new Exception(\sprintf('could not create a temporary file next to the checkpoint `%s`', $this->path));
        }

        try {
            $json = \json_encode($this->toArray(), \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR) . \PHP_EOL;

            if (false === \file_put_contents($temporaryPath, $json) || false === @\rename($temporaryPath, $this->path)) {
                throw new Exception(\sprintf('could not atomically write the checkpoint `%s`', $this->path));
            }
        } catch (JsonException $jsonException) {
            throw new Exception(\sprintf('could not encode the checkpoint `%s`', $this->path), 0, $jsonException);
        } finally {
            if (true === \is_file($temporaryPath)) {
                \unlink($temporaryPath);
            }
        }
    }
}
