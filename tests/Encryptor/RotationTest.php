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

/**
 * @internal
 *
 * Covers SDE-152 (explicit legacy salt version), SDE-153 (deterministic multi-salt lookup) and SDE-163
 * (encryptor-level unit coverage for multi-salt rotation).
 */
final class RotationTest extends TestCase
{
    private const SALT_V1 = 'rotation-test-salt-value-v1-12345';
    private const SALT_V2 = 'rotation-test-salt-value-v2-67890';
    private const SALT_V3 = 'rotation-test-salt-value-v3-abcde';

    /** @info SDE-163 — ciphertext written under v1 must still decrypt after rotating to v2 because the per-version keys are kept available */
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

    /** @info SDE-163 — new writes after rotation must use the current salt version */
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

    /** @info SDE-163 — swapping one salt out of the map after rotation must make previously-encrypted rows unreadable, proving per-version key isolation */
    public function testDecryptFailsWhenPreviousSaltDroppedFromMap(): void
    {
        $originalEncryptor = new Aes256Encryptor(['v1' => self::SALT_V1], 'v1');
        $ciphertextV1 = $originalEncryptor->encrypt('rotation-secret');

        $droppedEncryptor = new Aes256Encryptor(['v2' => self::SALT_V2], 'v2');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('unknown salt version `v1`');

        $droppedEncryptor->decrypt($ciphertextV1);
    }

    /** @info SDE-163 — constructor must refuse to accept a `currentSaltVersion` that is not in the salts map */
    public function testThrowsWhenCurrentSaltVersionMissingFromMap(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('current salt version `v3` not present');

        new Aes256Encryptor(['v1' => self::SALT_V1], 'v3');
    }

    /** @info SDE-152 — legacy four-part payloads must decrypt under the EXPLICIT `legacy_salt_version`, not ambient `currentSaltVersion` */
    public function testLegacyFourPartPayloadUsesExplicitLegacySaltVersionNotCurrent(): void
    {
        $legacyCiphertext = self::produceLegacyCiphertext(self::SALT_V1, 'legacy-secret');

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

    /** @info SDE-152 — if the operator rotates but keeps `legacy_salt_version` pointing at a NEW salt, legacy payloads must NOT silently decrypt under the wrong key */
    public function testLegacyPayloadFailsMacWhenLegacySaltVersionPointsToWrongKey(): void
    {
        $legacyCiphertext = self::produceLegacyCiphertext(self::SALT_V1, 'legacy-secret');

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

    /** @info SDE-152 — `legacy_salt_version` defaults to the first configured salt rather than `currentSaltVersion`, so rotation without any explicit legacy configuration keeps reading old 4-part rows */
    public function testLegacySaltVersionDefaultsToFirstConfiguredVersion(): void
    {
        $legacyCiphertext = self::produceLegacyCiphertext(self::SALT_V1, 'legacy-secret-default');

        $rotatedWithoutLegacyArg = new Aes256Encryptor(
            [
                'v1' => self::SALT_V1,
                'v2' => self::SALT_V2,
            ],
            'v2',
        );

        static::assertSame('legacy-secret-default', $rotatedWithoutLegacyArg->decrypt($legacyCiphertext));
    }

    /** @info SDE-152 — explicit `legacySaltVersion` that is not present in the salts map throws at construction */
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

    /** @info SDE-153 — deterministic encryptor produces different nonces per salt version so WHERE lookups need ALL versions' ciphertexts to match across a rotation */
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

        /** @info decryption still works for both because the MAC/encryption keys of v1 are retained */
        static::assertSame('lookup-me', $rotatedEncryptor->decrypt($ciphertextV1));
        static::assertSame('lookup-me', $rotatedEncryptor->decrypt($ciphertextV2));
    }

    /** @info SDE-153 — `encryptWithSaltVersion()` lets callers materialise one ciphertext per rotation epoch, producing a set of candidates for `WHERE IN (...)` lookups that do not silently miss pre-rotation rows */
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

    /** @info SDE-153 — `getActiveSaltVersions()` exposes the configured rotation window to callers building the IN (...) list */
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

    /** @info SDE-153 — `encryptWithSaltVersion()` against an unknown salt must throw instead of silently selecting the current key */
    public function testEncryptWithUnknownSaltVersionThrows(): void
    {
        $encryptor = new Aes256FixedEncryptor(['v1' => self::SALT_V1], 'v1');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('unknown salt version `v9`');

        $encryptor->encryptWithSaltVersion('lookup-me', 'v9');
    }

    /** @info SDE-154 — salt-version identifiers that would break the wire-format null-byte framing must be rejected at construction */
    public function testSaltVersionWithNullByteIsRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/invalid salt version identifier/');

        new Aes256Encryptor(["v1\0malicious" => self::SALT_V1], "v1\0malicious");
    }

    /** @info SDE-154 — salt-version identifiers with whitespace must be rejected */
    public function testSaltVersionWithSpaceIsRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/invalid salt version identifier/');

        new Aes256Encryptor(['v 1' => self::SALT_V1], 'v 1');
    }

    /** @info SDE-154 — salt-version identifiers with non-ASCII runes must be rejected */
    public function testSaltVersionWithNonAsciiIsRejected(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/invalid salt version identifier/');

        new Aes256Encryptor(['vé' => self::SALT_V1], 'vé');
    }

    /** @info SDE-154 — the accepted character set covers the conventional operator identifiers */
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

    /** @info builds a pre-v4.0.0 four-part ciphertext using the legacy HMAC layout so we can exercise SDE-152 without depending on real v3.x tags */
    private static function produceLegacyCiphertext(string $salt, string $plaintext): string
    {
        $algorithm = 'AES-256-CTR';
        $encryptionKey = \hash_hkdf('sha256', $salt, 32, 'encryption');
        $macKey = \hash_hkdf('sha256', $salt, 32, 'authentication');
        $nonce = \random_bytes(16);

        $ciphertext = \openssl_encrypt($plaintext, $algorithm, $encryptionKey, \OPENSSL_RAW_DATA, $nonce);
        \assert(false !== $ciphertext);

        $mac = \hash_hmac('sha256', $algorithm . $ciphertext . $nonce, $macKey, true);

        return \implode(
            "\0",
            [
                AbstractEncryptor::ENCRYPTION_MARKER,
                \base64_encode($ciphertext),
                \base64_encode($mac),
                \base64_encode($nonce),
            ],
        );
    }
}
