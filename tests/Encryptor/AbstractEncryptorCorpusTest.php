<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;

/**
 * The boundaries that matter for AES-256-CTR are the IV length and the block size, which coincide at 16 bytes — a stream cipher should not care, and these values prove it does not.
 *
 * @internal
 */
final class AbstractEncryptorCorpusTest extends TestCase
{
    private const SALT = 'abcdefghijklmnopqrstuvwxyz123456';

    /** @return iterable<string, array{string}> */
    public static function dataProviderSingleByteValue(): iterable
    {
        for ($byte = 0; $byte < 256; ++$byte) {
            yield 'byte ' . $byte => [\chr($byte)];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function dataProviderBoundaryLength(): iterable
    {
        foreach ([0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65] as $length) {
            yield 'length ' . $length => [\str_repeat('A', $length)];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function dataProviderAdversarialValue(): iterable
    {
        yield 'invalid utf-8 continuation' => ["\x80\x81\x82"];
        yield 'truncated utf-8 sequence' => ["\xC3"];
        yield 'overlong utf-8 encoding' => ["\xC0\x80"];
        yield 'all high bytes' => [\str_repeat("\xFF", 64)];
        yield 'all null bytes' => [\str_repeat("\0", 64)];
        yield 'glue only' => [AbstractEncryptor::GLUE];
        yield 'marker without glue' => [AbstractEncryptor::ENCRYPTION_MARKER];
        yield 'marker repeated' => [\str_repeat(AbstractEncryptor::ENCRYPTION_MARKER, 8)];
        yield 'sql injection shaped' => ["' OR 1=1 -- \0"];
        yield 'every byte value' => [self::buildEveryByteValue()];
    }

    #[DataProvider('dataProviderSingleByteValue')]
    #[DataProvider('dataProviderBoundaryLength')]
    #[DataProvider('dataProviderAdversarialValue')]
    public function testRandomNonceRoundTrip(string $value): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        static::assertSame($value, $aes256Encryptor->decrypt($aes256Encryptor->encrypt($value)));
    }

    #[DataProvider('dataProviderSingleByteValue')]
    #[DataProvider('dataProviderBoundaryLength')]
    #[DataProvider('dataProviderAdversarialValue')]
    public function testDeterministicRoundTrip(string $value): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        static::assertSame($value, $aes256FixedEncryptor->decrypt($aes256FixedEncryptor->encrypt($value)));
    }

    public function testMultiMegabyteRoundTrip(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $value = \random_bytes(2 * 1024 * 1024);

        static::assertSame($value, $aes256Encryptor->decrypt($aes256Encryptor->encrypt($value)));
    }

    public function testDistinctPlaintextsGetDistinctNonces(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        $nonces = [];

        for ($index = 0; $index < 512; ++$index) {
            $parts = \explode(AbstractEncryptor::GLUE, $aes256FixedEncryptor->encrypt('subject-' . $index));
            $nonces[] = $parts[5];
        }

        static::assertCount(512, \array_unique($nonces));
    }

    public function testBoundaryLengthPlaintextsDoNotShareAKeystream(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        $firstParts = \explode(AbstractEncryptor::GLUE, $aes256FixedEncryptor->encrypt(\str_repeat('A', 16)));
        $secondParts = \explode(AbstractEncryptor::GLUE, $aes256FixedEncryptor->encrypt(\str_repeat('A', 17)));

        static::assertNotSame($firstParts[5], $secondParts[5]);
    }

    private static function buildEveryByteValue(): string
    {
        $value = '';

        for ($byte = 0; $byte < 256; ++$byte) {
            $value .= \chr($byte);
        }

        return $value;
    }
}
