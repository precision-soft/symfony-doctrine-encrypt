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

/**
 * Each case invalidates exactly one segment, which is what makes the index observable: corrupting every segment at once cannot distinguish one from another, and strict base64 accepts `v1` and `default` too.
 *
 * @internal
 */
final class AbstractEncryptorEnvelopeShapeTest extends TestCase
{
    private const INVALID_BASE64 = '!!!not-base64!!!';

    private Aes256Encryptor $aes256Encryptor;

    protected function setUp(): void
    {
        $this->aes256Encryptor = new Aes256Encryptor(\str_repeat('a', 32));
    }

    /** @return iterable<string, array{int}> */
    public static function provideCurrentEnvelopeSegmentIndex(): iterable
    {
        yield 'ciphertext' => [3];
        yield 'message authentication code' => [4];
        yield 'nonce' => [5];
    }

    /** @return iterable<string, array{int}> */
    public static function provideLegacyEnvelopeSegmentIndex(): iterable
    {
        yield 'ciphertext' => [1];
        yield 'message authentication code' => [2];
        yield 'nonce' => [3];
    }

    public function testAMarkerThatIsNotFollowedByTheGlueByteIsNotTreatedAsEncrypted(): void
    {
        $lookalike = $this->buildLookalikeWithoutGlueAfterMarker();

        $encrypted = $this->aes256Encryptor->encrypt($lookalike);

        static::assertNotSame($lookalike, $encrypted);
        static::assertSame($lookalike, $this->aes256Encryptor->decrypt($encrypted));
    }

    public function testDecryptReturnsAMarkerThatIsNotFollowedByTheGlueByteUnchanged(): void
    {
        $lookalike = $this->buildLookalikeWithoutGlueAfterMarker();

        static::assertSame($lookalike, $this->aes256Encryptor->decrypt($lookalike));
    }

    #[DataProvider('provideCurrentEnvelopeSegmentIndex')]
    public function testACurrentEnvelopeWithOneUndecodableSegmentIsNotTreatedAsEncrypted(int $segmentIndex): void
    {
        $encryptedParts = \explode(AbstractEncryptor::GLUE, $this->aes256Encryptor->encrypt('payload'));

        static::assertCount(6, $encryptedParts);

        $encryptedParts[$segmentIndex] = self::INVALID_BASE64;
        $corrupted = \implode(AbstractEncryptor::GLUE, $encryptedParts);

        static::assertNotSame($corrupted, $this->aes256Encryptor->encrypt($corrupted));
    }

    #[DataProvider('provideLegacyEnvelopeSegmentIndex')]
    public function testALegacyEnvelopeWithOneUndecodableSegmentIsNotTreatedAsEncrypted(int $segmentIndex): void
    {
        $encryptedParts = [
            AbstractEncryptor::ENCRYPTION_MARKER,
            \base64_encode('ciphertext'),
            \base64_encode('message authentication code'),
            \base64_encode('nonce'),
        ];

        $encryptedParts[$segmentIndex] = self::INVALID_BASE64;
        $corrupted = \implode(AbstractEncryptor::GLUE, $encryptedParts);

        static::assertNotSame($corrupted, $this->aes256Encryptor->encrypt($corrupted));
    }

    /* every segment decodes, so the missing glue byte after the marker is the only thing making this plaintext */
    private function buildLookalikeWithoutGlueAfterMarker(): string
    {
        return \implode(
            AbstractEncryptor::GLUE,
            [
                AbstractEncryptor::ENCRYPTION_MARKER . 'X',
                \base64_encode('ciphertext'),
                \base64_encode('message authentication code'),
                \base64_encode('nonce'),
            ],
        );
    }
}
