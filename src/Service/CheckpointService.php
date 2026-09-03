<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Service;

use JsonException;
use PrecisionSoft\Doctrine\Encrypt\Dto\CheckpointScopeDto;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;

class CheckpointService
{
    public const FORMAT_VERSION = 2;

    protected const KEY_VERSION = 'version';
    protected const KEY_SCOPE = 'scope';
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
        protected readonly CheckpointScopeDto $scope,
        protected readonly string $path = '',
    ) {}

    public function getScope(): CheckpointScopeDto
    {
        return $this->scope;
    }

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

    /**
     * @param array<string, mixed> $identifierValues
     *
     * @throws Exception if a value is not an integer or a string, the only shapes a stored cursor can be bound from again
     */
    public function setIdentifierValues(string $className, array $identifierValues): static
    {
        foreach ($identifierValues as $fieldName => $value) {
            if (false === \is_int($value) && false === \is_string($value)) {
                throw new Exception(
                    \sprintf('the identifier `%s` of `%s` is not an integer or a string; a cursor cannot address it', $fieldName, $className),
                    0,
                    null,
                    ['className' => $className, 'fieldName' => $fieldName, 'type' => \get_debug_type($value)],
                );
            }
        }

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
            static::KEY_SCOPE => $this->scope->toArray(),
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

        if (true === \is_array($decoded) && 1 === ($decoded[static::KEY_VERSION] ?? null)) {
            throw new Exception(
                \sprintf('the checkpoint `%s` was written by a release before v4.7.0; finish that run with the release that wrote it, or delete the file', $this->path),
                0,
                null,
                ['path' => $this->path],
            );
        }

        if (
            false === \is_array($decoded)
            || static::FORMAT_VERSION !== ($decoded[static::KEY_VERSION] ?? null)
            || false === \is_array($decoded[static::KEY_ENTITIES] ?? null)
            || false === $this->isScope($decoded[static::KEY_SCOPE] ?? null)
        ) {
            throw new Exception(\sprintf('the checkpoint `%s` is not a version %d checkpoint', $this->path, static::FORMAT_VERSION));
        }

        $this->assertScope($decoded[static::KEY_SCOPE]);

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

    /** @phpstan-assert-if-true array{command: string, manager: string|null, saltVersion: string} $scope */
    protected function isScope(mixed $scope): bool
    {
        return true === \is_array($scope)
            && true === \is_string($scope['command'] ?? null)
            && (null === ($scope['manager'] ?? null) || true === \is_string($scope['manager']))
            && true === \is_string($scope['saltVersion'] ?? null);
    }

    /**
     * @param array{command: string, manager: string|null, saltVersion: string} $checkpointScope
     *
     * @throws Exception if the file belongs to another command, manager or target salt version, whose cursor would skip rows this run has never touched
     */
    protected function assertScope(array $checkpointScope): void
    {
        $runScope = $this->scope->toArray();

        $mismatch = match (true) {
            $checkpointScope['command'] !== $runScope['command'] => \sprintf('was written by `%s`, not by `%s`', $checkpointScope['command'], $runScope['command']),
            $checkpointScope['manager'] !== $runScope['manager'] => \sprintf('was written for the manager `%s`, not for `%s`', $checkpointScope['manager'] ?? 'default', $runScope['manager'] ?? 'default'),
            $checkpointScope['saltVersion'] !== $runScope['saltVersion'] => \sprintf('was written towards the salt version `%s`, not `%s`', $checkpointScope['saltVersion'], $runScope['saltVersion']),
            default => null,
        };

        if (null === $mismatch) {
            return;
        }

        throw new Exception(
            \sprintf('the checkpoint `%s` %s', $this->path, $mismatch),
            0,
            null,
            ['path' => $this->path, 'checkpointScope' => $checkpointScope, 'runScope' => $runScope],
        );
    }

    /* a short write is a success to `file_put_contents()`, so the byte count is compared and the data is synced before the rename makes it the checkpoint */
    protected function writeFile(string $path, string $contents): bool
    {
        $handle = @\fopen($path, 'wb');

        if (false === $handle) {
            return false;
        }

        try {
            return \strlen($contents) === $this->writeBytes($handle, $contents)
                && true === \fflush($handle)
                && true === \fsync($handle);
        } finally {
            \fclose($handle);
        }
    }

    /** @param resource $handle */
    protected function writeBytes($handle, string $contents): int|false
    {
        return \fwrite($handle, $contents);
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

            if (false === $this->writeFile($temporaryPath, $json) || false === @\rename($temporaryPath, $this->path)) {
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
