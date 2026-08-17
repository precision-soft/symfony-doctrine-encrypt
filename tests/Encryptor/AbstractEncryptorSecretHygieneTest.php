<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use Throwable;

/**
 * @internal
 */
final class AbstractEncryptorSecretHygieneTest extends TestCase
{
    private const SALT = 'hygiene-salt-abcdefghijklmnopqrs';

    /** @return iterable<string, array{callable(Aes256Encryptor): string}> */
    public static function dataProviderSafeDumpPath(): iterable
    {
        yield 'print_r' => [static fn(Aes256Encryptor $aes256Encryptor): string => \print_r($aes256Encryptor, true)];
        yield 'json_encode' => [static fn(Aes256Encryptor $aes256Encryptor): string => (string)\json_encode($aes256Encryptor)];
        yield 'var_dump' => [
            static function (Aes256Encryptor $aes256Encryptor): string {
                \ob_start();
                \var_dump($aes256Encryptor);

                return (string)\ob_get_clean();
            },
        ];
    }

    /**
     * @param callable(Aes256Encryptor): string $dumpPath
     *
     */
    #[DataProvider('dataProviderSafeDumpPath')]
    public function testDumpPathDoesNotExposeKeyMaterial(callable $dumpPath): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->assertContainsNoSecret($dumpPath($aes256Encryptor));
    }

    public function testSerializeRefusesToCarryKeyMaterial(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('must not be serialized');

        \serialize($aes256Encryptor);
    }

    public function testUnserializeRefusesToRebuildAnEncryptor(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('must not be serialized');

        \unserialize(
            'O:56:"PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor":0:{}',
        );
    }

    /* the exposure cannot be closed in code, so this exists to notice a future PHP release closing the gap rather than assuming it */
    public function testVarExportRemainsAnUncloseableExposure(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $exported = \var_export($aes256Encryptor, true);

        static::assertStringContainsString('encryptionKeysBySaltVersion', $exported);
        static::assertStringContainsString('macKeysBySaltVersion', $exported);
        static::assertStringNotContainsString('encryptionKeysBySaltVersion', \print_r($aes256Encryptor, true));

        /* var_export escapes NUL bytes as a concatenation, so only the longest NUL-free run of the key can appear contiguously */
        static::assertStringContainsString(
            self::getLongestNullFreeRun(\hash_hkdf('sha256', self::SALT, 32, 'encryption')),
            $exported,
        );
    }

    /** @return iterable<string, array{array<string, string>|string, string, string|null}> */
    public static function dataProviderConstructorRejection(): iterable
    {
        yield 'empty salts map' => [[], 'default', null];
        yield 'current version absent' => [['v1' => self::SALT], 'nope', null];
        yield 'salt below minimum length' => [['v1' => \str_repeat('x', 31)], 'v1', null];
        yield 'invalid version identifier' => [['bad version!' => self::SALT], 'bad version!', null];
        yield 'legacy version absent' => [['v1' => self::SALT], 'v1', 'nope'];
    }

    /**
     * @param array<string, string>|string $saltsByVersion
     *
     * `#[\SensitiveParameter]` is what keeps the salt out of the trace — `getTraceAsString()` otherwise prints the first 15 characters of every string argument
     */
    #[DataProvider('dataProviderConstructorRejection')]
    public function testConstructorRejectionLeaksNothing(
        array|string $saltsByVersion,
        string $currentSaltVersion,
        ?string $legacySaltVersion,
    ): void {
        try {
            new Aes256Encryptor($saltsByVersion, $currentSaltVersion, $legacySaltVersion);
        } catch (Exception $exception) {
            $this->assertContainsNoSecret($exception->getMessage());
            $this->assertContainsNoSecret($exception->getTraceAsString());

            return;
        }

        static::fail('the constructor accepted an invalid salt configuration');
    }

    public function testRuntimeFailuresLeakNothing(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        try {
            $aes256FixedEncryptor->encryptWithSaltVersion('subject', 'no-such-version');
        } catch (Throwable $throwable) {
            $this->assertContainsNoSecret($throwable->getMessage());
            $this->assertContainsNoSecret($throwable->getTraceAsString());
        }

        try {
            $aes256FixedEncryptor->decrypt("<ENC>\0v1\0default\0!!!\0!!!\0!!!");
        } catch (Throwable $throwable) {
            $this->assertContainsNoSecret($throwable->getMessage());
            $this->assertContainsNoSecret($throwable->getTraceAsString());
        }
    }

    public function testDebugInfoExposesOnlyTheRotationShape(): void
    {
        $aes256Encryptor = new Aes256Encryptor(['v1' => self::SALT, 'v2' => \str_repeat('z', 32)], 'v2', 'v1');

        static::assertSame(
            [
                'algorithm' => 'AES-256-CTR',
                'saltVersions' => ['v1', 'v2'],
                'currentSaltVersion' => 'v2',
                'legacySaltVersion' => 'v1',
            ],
            $aes256Encryptor->__debugInfo(),
        );
    }

    private static function getLongestNullFreeRun(string $value): string
    {
        $longestRun = '';

        foreach (\explode("\0", $value) as $run) {
            if (\strlen($run) > \strlen($longestRun)) {
                $longestRun = $run;
            }
        }

        return $longestRun;
    }

    private function assertContainsNoSecret(string $haystack): void
    {
        static::assertStringNotContainsString(self::SALT, $haystack);
        static::assertStringNotContainsString(\substr(self::SALT, 0, 15), $haystack);

        foreach (['encryption', 'authentication', 'nonce'] as $information) {
            $derivedKey = \hash_hkdf('sha256', self::SALT, 32, $information);

            static::assertStringNotContainsString($derivedKey, $haystack);
            static::assertStringNotContainsString(\bin2hex($derivedKey), $haystack);
        }
    }
}
