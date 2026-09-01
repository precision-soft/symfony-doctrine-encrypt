<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Service;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\CheckpointService;

/** @internal */
final class CheckpointServiceTest extends TestCase
{
    private const FIRST_CLASS_NAME = 'App\\Entity\\FirstSubject';
    private const SECOND_CLASS_NAME = 'App\\Entity\\SecondSubject';
    private const THIRD_CLASS_NAME = 'App\\Entity\\ThirdSubject';

    private string $directory = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = \sys_get_temp_dir() . '/checkpoint-' . \bin2hex(\random_bytes(8));

        \mkdir($this->directory, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (\glob($this->directory . '/*') ?: [] as $path) {
            if (true === \is_file($path)) {
                \unlink($path);
            }
        }

        if (true === \is_dir($this->directory)) {
            \rmdir($this->directory);
        }

        parent::tearDown();
    }

    public function testWithoutAPathNothingIsWritten(): void
    {
        $checkpointService = new CheckpointService();

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

        (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 42]);

        static::assertSame(['id' => 42], (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertNull((new CheckpointService($path))->getIdentifierValues(static::SECOND_CLASS_NAME));
    }

    public function testWriteLeavesOnlyTheCheckpointBehindWithOwnerOnlyPermissions(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($path);

        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);
        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 2]);

        static::assertSame([$path], \glob($this->directory . '/*'));
        static::assertSame(0600, \fileperms($path) & 0777);
        static::assertSame(['id' => 2], (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME));
    }

    public function testWriteCreatesTheMissingDirectory(): void
    {
        $path = $this->directory . '/nested/deeper/checkpoint.json';

        (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 3]);

        static::assertFileExists($path);
        static::assertSame(['id' => 3], (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME));

        \unlink($path);
        \rmdir($this->directory . '/nested/deeper');
        \rmdir($this->directory . '/nested');
    }

    public function testMarkCompletedPersistsEachClassNameOnce(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($path);

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
        $checkpointService = new CheckpointService($path);

        $checkpointService->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 900]);
        $checkpointService->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 800]);
        $checkpointService->markCompleted([static::FIRST_CLASS_NAME]);

        $resumed = new CheckpointService($path);

        static::assertNull($resumed->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertSame(['id' => 800], $resumed->getIdentifierValues(static::SECOND_CLASS_NAME));
    }

    public function testACompletedClassIsNotCarriedIntoTheNextRun(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($path))->markCompleted([static::FIRST_CLASS_NAME]);

        $resumed = new CheckpointService($path);
        $resumed->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 5]);

        static::assertSame([], $this->readKey($path, 'completed'));
    }

    public function testSettingACursorMergesIntoAnExistingFile(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);
        (new CheckpointService($path))->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 2]);

        $checkpointService = new CheckpointService($path);

        static::assertSame(['id' => 1], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));
        static::assertSame(['id' => 2], $checkpointService->getIdentifierValues(static::SECOND_CLASS_NAME));
    }

    public function testMarkingCompletedKeepsWhatTheFileAlreadyHeld(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($path))->setIdentifierValues(static::SECOND_CLASS_NAME, ['id' => 2]);
        (new CheckpointService($path))->markCompleted([static::FIRST_CLASS_NAME]);

        static::assertSame(['id' => 2], (new CheckpointService($path))->getIdentifierValues(static::SECOND_CLASS_NAME));
        static::assertSame([static::FIRST_CLASS_NAME], $this->readKey($path, 'completed'));
    }

    public function testCompletedStaysAListWhenAClassNameRepeats(): void
    {
        $path = $this->directory . '/checkpoint.json';
        $checkpointService = new CheckpointService($path);

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
        (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 10]);

        $checkpointService = new CheckpointService($path);

        static::assertSame(['id' => 10], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));

        (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 99]);

        static::assertSame(['id' => 10], $checkpointService->getIdentifierValues(static::FIRST_CLASS_NAME));
    }

    public function testTheWrittenFileEndsWithANewline(): void
    {
        $path = $this->directory . '/checkpoint.json';

        (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => 1]);

        static::assertStringEndsWith('}' . \PHP_EOL, (string)\file_get_contents($path));
    }

    public function testAFailedWriteLeavesNoTemporaryFileBehind(): void
    {
        $path = $this->directory . '/checkpoint.json';

        try {
            /* an identifier that is not valid utf-8 is the cheapest way to make the encode fail after the temporary file exists */
            (new CheckpointService($path))->setIdentifierValues(static::FIRST_CLASS_NAME, ['id' => "\xB1\x31"]);

            static::fail('expected the checkpoint encode to fail');
        } catch (Exception $exception) {
            static::assertStringContainsString('could not encode the checkpoint', $exception->getMessage());
        }

        static::assertSame([], \glob($this->directory . '/*'));
    }

    public function testToArrayCarriesTheFormatVersion(): void
    {
        static::assertSame(
            ['version' => CheckpointService::FORMAT_VERSION, 'entities' => [], 'completed' => []],
            (new CheckpointService())->toArray(),
        );
    }

    public function testRejectsAFileThatIsNotJson(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, 'not json at all');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not valid json');

        (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testRejectsAnUnknownFormatVersion(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 2, 'entities' => [], 'completed' => []]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not a version 1 checkpoint');

        (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testRejectsAMissingEntitiesKey(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 1]));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('is not a version 1 checkpoint');

        (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME);
    }

    public function testReadsAFileWrittenWithoutTheCompletedKey(): void
    {
        $path = $this->directory . '/checkpoint.json';
        \file_put_contents($path, \json_encode(['version' => 1, 'entities' => [static::FIRST_CLASS_NAME => ['id' => 11]]]));

        static::assertSame(['id' => 11], (new CheckpointService($path))->getIdentifierValues(static::FIRST_CLASS_NAME));
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
