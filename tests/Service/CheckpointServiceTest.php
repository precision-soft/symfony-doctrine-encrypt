<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Dto\CheckpointScopeDto;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\ShortWriteCheckpointService;

/** @internal */
final class CheckpointServiceTest extends TestCase
{
    private const FIRST_CLASS_NAME = 'App\\Entity\\FirstSubject';
    private const SECOND_CLASS_NAME = 'App\\Entity\\SecondSubject';
    private const THIRD_CLASS_NAME = 'App\\Entity\\ThirdSubject';

    private string $directory = '';

    private CheckpointScopeDto $scope;

    public function testWithoutAPathNothingIsWritten(): void
    {
        $checkpointService = new CheckpointService($this->scope);

        static::assertSame('', $checkpointService->getPath());
        static::assertFalse($checkpointService->hasPath());

        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 7]);
        $checkpointService->markCompleted([static::FIRST_CLASS_NAME]);

        static::assertSame(['id' => 7], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertSame([], \glob($this->directory . '/*'));
    }

    public function testRoundTripsIdentifierValuesThroughTheFile(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 42]);

        static::assertSame(['id' => 42], (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertNull((new CheckpointService($this->scope, $path))->getIdentifierValues(static::SECOND_CLASS_NAME));
    }

    public function testWriteLeavesOnlyTheCheckpointBehindWithOwnerOnlyPermissions(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($this->scope, $path);

        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);
        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 2]);

        static::assertSame([$path], \glob($this->directory . '/*'));
        static::assertSame(0600, \fileperms($path) & 0777);
        static::assertSame(['id' => 2], (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME));
    }

    public function testWriteCreatesTheMissingDirectory(): void
    {
        $path = $this->directory . '/nested/deeper/checkpoint.json';

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 3]);

        static::assertFileExists($path);
        static::assertSame(['id' => 3], (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME));

        \unlink($path);
        \rmdir($this->directory . '/nested/deeper');
        \rmdir($this->directory . '/nested');
    }

    public function testMarkCompletedPersistsEachClassNameOnce(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($this->scope, $path);

        $checkpointService->markCompleted([static::FIRST_CLASS_NAME, static::SECOND_CLASS_NAME]);
        $checkpointService->markCompleted([static::FIRST_CLASS_NAME]);

        static::assertSame(
            [static::FIRST_CLASS_NAME, static::SECOND_CLASS_NAME],
            $this->readKey($path, 'completed'),
        );
    }

    public function testACompletedClassStartsOverOnTheNextRun(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($this->scope, $path);

        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 900]);
        $checkpointService->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 800]);
        $checkpointService->markCompleted([static::FIRST_CLASS_NAME]);

        $resumed = new CheckpointService($this->scope, $path);

        static::assertNull($resumed->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertSame(['id' => 800], $resumed->getIdentifierValues(static::SECOND_CLASS_NAME));
    }

    public function testACompletedClassIsNotCarriedIntoTheNextRun(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($this->scope, $path))->markCompleted([static::FIRST_CLASS_NAME]);

        $resumed = new CheckpointService($this->scope, $path);
        $resumed->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 5]);

        static::assertSame([], $this->readKey($path, 'completed'));
    }

    public function testSettingACursorMergesIntoAnExistingFile(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 2]);

        $checkpointService = new CheckpointService($this->scope, $path);

        static::assertSame(['id' => 1], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertSame(['id' => 2], $checkpointService->getIdentifierValues(static::SECOND_CLASS_NAME));
    }

    public function testMarkingCompletedKeepsWhatTheFileAlreadyHeld(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 2]);
        (new CheckpointService($this->scope, $path))->markCompleted([static::FIRST_CLASS_NAME]);

        static::assertSame(['id' => 2], (new CheckpointService($this->scope, $path))->getIdentifierValues(static::SECOND_CLASS_NAME));
        static::assertSame([static::FIRST_CLASS_NAME], $this->readKey($path, 'completed'));
    }

    public function testCompletedStaysAListWhenAClassNameRepeats(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($this->scope, $path);

        $checkpointService->markCompleted([static::FIRST_CLASS_NAME, static::SECOND_CLASS_NAME]);
        $checkpointService->markCompleted([static::FIRST_CLASS_NAME, static::THIRD_CLASS_NAME]);

        static::assertSame(
            [static::FIRST_CLASS_NAME, static::SECOND_CLASS_NAME, static::THIRD_CLASS_NAME],
            $this->readKey($path, 'completed'),
        );
    }

    public function testTheFileIsReadOnlyOnce(): void
    {
        $path = $this->directory . '/checkpoint.json';
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 10]);

        $checkpointService = new CheckpointService($this->scope, $path);

        static::assertSame(['id' => 10], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 99]);

        static::assertSame(['id' => 10], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));
    }

    public function testTheWrittenFileEndsWithANewline(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);

        static::assertStringEndsWith('}' . \PHP_EOL, (string)\file_get_contents($path));
    }

    public function testAFailedWriteLeavesNoTemporaryFileBehind(): void
    {
        $path = $this->directory . '/checkpoint.json';

        try {
            /* an identifier that is not valid utf-8 is the cheapest way to make the encode fail after the temporary file exists */
            (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => "\xB1\x31"]);

            static::fail('expected the checkpoint encode to fail');
        } catch (Exception $exception) {
            static::assertStringContainsString('could not encode the checkpoint', $exception->getMessage());
        }

        static::assertSame([], \glob($this->directory . '/*'));
    }

    public function testToArrayCarriesTheFormatVersion(): void
    {
        static::assertSame(
            [
                'version' => CheckpointService::FORMAT_VERSION,
                'scope' => ['command' => 'precision-soft:doctrine:database:rotate', 'manager' => null, 'saltVersion' => 'v2'],
                'entities' => [],
                'completed' => [],
            ],
            (new CheckpointService($this->scope))->toArray(),
        );
    }

    public function testANonScalarIdentifierValueIsRefusedAtWriteTime(): void
    {
        $path = $this->directory . '/checkpoint.json';

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the identifier `id` of `App\\Entity\\FirstSubject` is not an integer or a string; a cursor cannot address it');

        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => new DateTimeImmutable()]);
    }

    public function testANonScalarIdentifierValueIsRefusedEvenWithoutAPath(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not an integer or a string');

        (new CheckpointService($this->scope))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => [1, 2]]);
    }

    public function testAShortWriteIsRefusedAndLeavesTheCheckpointUntouched(): void
    {
        $path = $this->directory . '/checkpoint.json';
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);
        $before = (string)\file_get_contents($path);

        try {
            (new ShortWriteCheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 2]);

            static::fail('expected the short write to be refused');
        } catch (Exception $exception) {
            static::assertStringContainsString('could not atomically write the checkpoint', $exception->getMessage());
        }

        static::assertSame($before, \file_get_contents($path));
        static::assertSame([$path], \glob($this->directory . '/*'));
        static::assertSame(['id' => 1], (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME));
    }

    public function testToArrayCarriesTheScope(): void
    {
        $scope = new CheckpointScopeDto('precision-soft:doctrine:database:encrypt', 'secondary', 'v3');

        static::assertSame(
            ['command' => 'precision-soft:doctrine:database:encrypt', 'manager' => 'secondary', 'saltVersion' => 'v3'],
            (new CheckpointService($scope))->toArray()['scope'],
        );
        static::assertSame($scope, (new CheckpointService($scope))->getScope());
    }

    public function testACheckpointWrittenByAnotherCommandIsRejected(): void
    {
        $path = $this->directory . '/checkpoint.json';
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 5]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('was written by `precision-soft:doctrine:database:rotate`, not by `precision-soft:doctrine:database:encrypt`');

        (new CheckpointService(new CheckpointScopeDto('precision-soft:doctrine:database:encrypt', null, 'v2'), $path))
            ->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testACheckpointWrittenForAnotherManagerIsRejected(): void
    {
        $path = $this->directory . '/checkpoint.json';
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 5]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('was written for the manager `default`, not for `secondary`');

        (new CheckpointService(new CheckpointScopeDto('precision-soft:doctrine:database:rotate', 'secondary', 'v2'), $path))
            ->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testACheckpointWrittenTowardsAnotherSaltVersionIsRejected(): void
    {
        $path = $this->directory . '/checkpoint.json';
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 5]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('was written towards the salt version `v2`, not `v3`');

        (new CheckpointService(new CheckpointScopeDto('precision-soft:doctrine:database:rotate', null, 'v3'), $path))
            ->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testAScopeMismatchCarriesBothScopesInTheContext(): void
    {
        $path = $this->directory . '/checkpoint.json';
        (new CheckpointService($this->scope, $path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 5]);

        $foreignScope = new CheckpointScopeDto('precision-soft:doctrine:database:decrypt', 'secondary', 'v3');

        try {
            (new CheckpointService($foreignScope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);

            static::fail('expected the foreign checkpoint to be rejected');
        } catch (Exception $exception) {
            static::assertSame(
                ['path' => $path, 'checkpointScope' => $this->scope->toArray(), 'runScope' => $foreignScope->toArray()],
                $exception->getContext(),
            );
        }
    }

    public function testAVersionOneCheckpointIsRejectedWithAnUpgradeMessage(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 1, 'entities' => [static::FIRST_CLASS_NAME => ['id' => 11]], 'completed' => []]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('was written by a release before v4.7.0; finish that run with the release that wrote it, or delete the file');

        (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testACheckpointWithoutAScopeIsRejected(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 2, 'entities' => [], 'completed' => []]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not a version 2 checkpoint');

        (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testACheckpointWithAMalformedScopeIsRejected(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 2, 'scope' => ['command' => 7], 'entities' => [], 'completed' => []]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not a version 2 checkpoint');

        (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testRejectsAFileThatIsNotJson(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, 'not json at all');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not valid json');

        (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testRejectsAnUnknownFormatVersion(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 3, 'scope' => $this->scope->toArray(), 'entities' => [], 'completed' => []]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not a version 2 checkpoint');

        (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testRejectsAMissingEntitiesKey(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 2, 'scope' => $this->scope->toArray()]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not a version 2 checkpoint');

        (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testReadsAFileWrittenWithoutTheCompletedKey(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 2, 'scope' => $this->scope->toArray(), 'entities' => [static::FIRST_CLASS_NAME => ['id' => 11]]]));

        static::assertSame(['id' => 11], (new CheckpointService($this->scope, $path))->getIdentifierValues(static::FIRST_CLASS_NAME));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = \sys_get_temp_dir() . '/checkpoint-' . \bin2hex(\random_bytes(8));
        $this->scope = new CheckpointScopeDto('precision-soft:doctrine:database:rotate', null, 'v2');

        \mkdir($this->directory, 0700, true);
    }

    protected function tearDown(): void
    {
        $paths = \glob($this->directory . '/*');

        if (false === $paths) {
            $paths = [];
        }

        foreach ($paths as $path) {
            if (true === \is_file($path)) {
                \unlink($path);
            }
        }

        if (true === \is_dir($this->directory)) {
            \rmdir($this->directory);
        }

        parent::tearDown();
    }

    /** @return mixed[] */
    private function readKey(string $path, string $key): array
    {
        $decoded = \json_decode((string)\file_get_contents($path), true, 512, \JSON_THROW_ON_ERROR);

        static::assertIsArray($decoded);
        static::assertArrayHasKey($key, $decoded);
        static::assertIsArray($decoded[$key]);

        return $decoded[$key];
    }
}
