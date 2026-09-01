<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Test\Utility\LegacyCiphertext;

/**
 * @internal
 */
final class RotationTest extends TestCase
{
    private const SALT_V1 = 'rotation-test-salt-value-v1-12345';
    private const SALT_V2 = 'rotation-test-salt-value-v2-67890';
    private const SALT_V3 = 'rotation-test-salt-value-v3-abcde';

    public function testDecryptsCiphertextWrittenUnderPreviousSaltVersion(): void
    {
        $singleVersionEncryptor = new Aes256Encryptor(
            ['v1' => self::SALT_V1],
            'v1',
        );
        $ciphertextV1 = $singleVersionEncryptor->encrypt('rotation-secret');

        $rotatedEncryptor = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        static::assertSame('rotation-secret', $rotatedEncryptor->decrypt($ciphertextV1));
    }

    public function testNewWritesUseCurrentSaltVersionAfterRotation(): void
    {
        $rotatedEncryptor = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        $ciphertext = $rotatedEncryptor->encrypt('rotation-secret');
        $parts = \explode("\0", $ciphertext);

        static::assertSame('v2', $parts[2]);
    }

    public function testDecryptFailsWhenPreviousSaltDroppedFromMap(): void
    {
        $originalEncryptor = new Aes256Encryptor(['v1' => self::SALT_V1], 'v1');
        $ciphertextV1 = $originalEncryptor->encrypt('rotation-secret');

        $droppedEncryptor = new Aes256Encryptor(['v2' => self::SALT_V2], 'v2');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('unknown salt version `v1`');

        $droppedEncryptor->decrypt($ciphertextV1);
    }

    public function testThrowsWhenCurrentSaltVersionMissingFromMap(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('current salt version `v3` not present');

        new Aes256Encryptor(['v1' => self::SALT_V1], 'v3');
    }

    public function testLegacyFourPartPayloadUsesExplicitLegacySaltVersionNotCurrent(): void
    {
        $legacyCiphertext = LegacyCiphertext::produce(self::SALT_V1, 'legacy-secret');

        $rotatedEncryptor = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
            'v1',
        );

        static::assertSame('legacy-secret', $rotatedEncryptor->decrypt($legacyCiphertext));
    }

    public function testLegacyPayloadFailsMacWhenLegacySaltVersionPointsToWrongKey(): void
    {
        $legacyCiphertext = LegacyCiphertext::produce(self::SALT_V1, 'legacy-secret');

        $wrongEncryptor = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
            'v2',
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $wrongEncryptor->decrypt($legacyCiphertext);
    }

    public function testLegacySaltVersionDefaultsToFirstConfiguredVersion(): void
    {
        $legacyCiphertext = LegacyCiphertext::produce(self::SALT_V1, 'legacy-secret-default');

        $rotatedWithoutLegacyArg = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        static::assertSame('legacy-secret-default', $rotatedWithoutLegacyArg->decrypt($legacyCiphertext));
    }

    public function testThrowsWhenLegacySaltVersionNotInSaltsMap(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('legacy salt version `missing` not present');

        new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
            'missing',
        );
    }

    public function testDeterministicNonceIsVersionSpecificAcrossRotation(): void
    {
        $singleVersionEncryptor = new Aes256FixedEncryptor(['v1' => self::SALT_V1], 'v1');
        $ciphertextV1 = $singleVersionEncryptor->encrypt('lookup-me');

        $rotatedEncryptor = new Aes256FixedEncryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );
        $ciphertextV2 = $rotatedEncryptor->encrypt('lookup-me');

        static::assertNotSame(
            $ciphertextV1,
            $ciphertextV2,
            'rotation-time ciphertext must differ from legacy-time ciphertext',
        );

        static::assertSame('lookup-me', $rotatedEncryptor->decrypt($ciphertextV1));
        static::assertSame('lookup-me', $rotatedEncryptor->decrypt($ciphertextV2));
    }

    public function testEncryptWithSaltVersionProducesMatchingCiphertextPerEpoch(): void
    {
        $singleVersionEncryptor = new Aes256FixedEncryptor(['v1' => self::SALT_V1], 'v1');
        $ciphertextWrittenUnderV1 = $singleVersionEncryptor->encrypt('lookup-me');

        $rotatedEncryptor = new Aes256FixedEncryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        $candidateV1 = $rotatedEncryptor->encryptWithSaltVersion('lookup-me', 'v1');
        $candidateV2 = $rotatedEncryptor->encryptWithSaltVersion('lookup-me', 'v2');

        static::assertSame(
            $ciphertextWrittenUnderV1,
            $candidateV1,
            'candidate for v1 must byte-match the ciphertext originally written under v1 (deterministic + same nonce key)',
        );
        static::assertNotSame(
            $candidateV1,
            $candidateV2,
            'different salt versions must produce different ciphertexts (proves per-version nonce derivation)',
        );
    }

    public function testGetActiveSaltVersionsReturnsAllConfiguredVersionsInOrder(): void
    {
        $encryptor = new Aes256FixedEncryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
                'v3' => self::SALT_V3,
            ],
            'v2',
        );

        static::assertSame(['v1', 'v2', 'v3'], $encryptor->getActiveSaltVersions());
    }

    public function testEncryptWithUnknownSaltVersionThrows(): void
    {
        $encryptor = new Aes256FixedEncryptor(['v1' => self::SALT_V1], 'v1');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('unknown salt version `v9`');

        $encryptor->encryptWithSaltVersion('lookup-me', 'v9');
    }

    public function testSaltVersionWithNullByteIsRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/invalid salt version identifier/');

        new Aes256Encryptor(["v1\0malicious" => self::SALT_V1], "v1\0malicious");
    }

    public function testSaltVersionWithSpaceIsRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/invalid salt version identifier/');

        new Aes256Encryptor(['v 1' => self::SALT_V1], 'v 1');
    }

    public function testSaltVersionWithNonAsciiIsRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/invalid salt version identifier/');

        new Aes256Encryptor(['vé' => self::SALT_V1], 'vé');
    }

    public function testSaltVersionWithAllowedCharactersIsAccepted(): void
    {
        $encryptor = new Aes256Encryptor(
            [
                'v1_2026-04' => self::SALT_V1,
                'v2_2026-05' => self::SALT_V2,
            ],
            'v2_2026-05',
        );

        static::assertSame('ok', $encryptor->decrypt($encryptor->encrypt('ok')));
    }

    public function testGetCurrentSaltVersionReturnsTheVersionNewWritesUse(): void
    {
        $encryptor = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        $parts = \explode(AbstractEncryptor::GLUE, $encryptor->encrypt('rotation-secret'));

        static::assertSame('v2', $encryptor->getCurrentSaltVersion());
        static::assertSame($encryptor->getCurrentSaltVersion(), $parts[2]);
    }

    public function testGetCurrentEnvelopePrefixIsExactlyWhatEncryptWrites(): void
    {
        $encryptor = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        $parts = \explode(AbstractEncryptor::GLUE, $encryptor->encrypt('rotation-secret'));

        static::assertSame(
            $parts[0] . AbstractEncryptor::GLUE . $parts[1] . AbstractEncryptor::GLUE . $parts[2] . AbstractEncryptor::GLUE,
            $encryptor->getCurrentEnvelopePrefix(),
        );
    }

    public function testSaltVersionsDifferingOnlyByLetterCaseAreRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('salt versions must not differ only by letter case');

        new Aes256Encryptor(
            [
                'v2' => self::SALT_V1,
                'V2' => self::SALT_V2,
            ],
            'v2',
        );
    }
}
