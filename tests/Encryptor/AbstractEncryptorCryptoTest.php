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
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;

/** @internal */
final class AbstractEncryptorCryptoTest extends TestCase
{
    private const SALT = 'abcdefghijklmnopqrstuvwxyz123456';

    public function testDerivedKeysAreConsistentAcrossInstances(): void
    {
        $firstAes256Encryptor = new Aes256Encryptor(self::SALT);
        $secondAes256Encryptor = new Aes256Encryptor(self::SALT);

        $plaintext = 'deterministic-key-test';

        $encrypted = $firstAes256Encryptor->encrypt($plaintext);
        $decrypted = $secondAes256Encryptor->decrypt($encrypted);

        static::assertSame($plaintext, $decrypted);
    }

    public function testDifferentSaltsProduceDifferentKeys(): void
    {
        $saltA = \str_repeat('a', 32);
        $saltB = \str_repeat('b', 32);

        $firstAes256FixedEncryptor = new Aes256FixedEncryptor($saltA);
        $secondAes256FixedEncryptor = new Aes256FixedEncryptor($saltB);

        $plaintext = 'cross-key-test';

        $encryptedA = $firstAes256FixedEncryptor->encrypt($plaintext);
        $encryptedB = $secondAes256FixedEncryptor->encrypt($plaintext);

        static::assertNotSame($encryptedA, $encryptedB);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $secondAes256FixedEncryptor->decrypt($encryptedA);
    }

    /** @info indirect test: if encKey == macKey, swapping ciphertext and mac would still verify */
    public function testHkdfDerivesSeparateEncryptionAndMacKeys(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('verify-key-separation');

        $parts = \explode("\0", $encrypted);
        static::assertCount(6, $parts);

        [$marker, $version, $saltVersion, $ciphertext, $mac, $nonce] = $parts;
        $swapped = \implode("\0", [$marker, $version, $saltVersion, $mac, $ciphertext, $nonce]);

        $this->expectException(Exception::class);

        $aes256Encryptor->decrypt($swapped);
    }

    public function testTamperedCiphertextDetected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('mac-test');

        $parts = \explode("\0", $encrypted);
        $rawCiphertext = \base64_decode($parts[3], true);
        $rawCiphertext[0] = \chr(\ord($rawCiphertext[0]) ^ 0x01);
        $parts[3] = \base64_encode($rawCiphertext);
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testTamperedNonceDetected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('nonce-tamper-test');

        $parts = \explode("\0", $encrypted);
        $rawNonce = \base64_decode($parts[5], true);
        $rawNonce[0] = \chr(\ord($rawNonce[0]) ^ 0x01);
        $parts[5] = \base64_encode($rawNonce);
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testTamperedMacDetected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('marker-test');

        $parts = \explode("\0", $encrypted);
        $parts[4] = \base64_encode(\random_bytes(32));
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testTamperedVersionFieldDetected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('version-tamper-test');

        $parts = \explode("\0", $encrypted);
        $parts[1] = 'v2';
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt($tampered);
    }

    /** @info MAC covers version + salt version + algorithm + ciphertext + nonce; verifies structure and base64 validity */
    public function testMacCoversAlgorithmIdentifier(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $encrypted = $aes256FixedEncryptor->encrypt('algo-coverage-test');

        $parts = \explode("\0", $encrypted);
        static::assertCount(6, $parts);
        static::assertSame(AbstractEncryptor::ENCRYPTION_MARKER, $parts[0]);
        static::assertSame(AbstractEncryptor::FORMAT_VERSION_V1, $parts[1]);
        static::assertSame(AbstractEncryptor::DEFAULT_SALT_VERSION, $parts[2]);
        static::assertSame(true, false !== \base64_decode($parts[3], true));
        static::assertSame(true, false !== \base64_decode($parts[4], true));
        static::assertSame(true, false !== \base64_decode($parts[5], true));
        static::assertSame(32, \strlen(\base64_decode($parts[4], true)));
    }

    public function testDecryptWithTooFewPartsThrowsException(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate ciphertext');

        $aes256Encryptor->decrypt(AbstractEncryptor::ENCRYPTION_MARKER . "\0" . \base64_encode('data'));
    }

    public function testDecryptWithTooManyPartsThrowsException(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate ciphertext');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            AbstractEncryptor::FORMAT_VERSION_V1 . "\0" .
            AbstractEncryptor::DEFAULT_SALT_VERSION . "\0" .
            \base64_encode('a') . "\0" .
            \base64_encode('b') . "\0" .
            \base64_encode('c') . "\0" .
            \base64_encode('d'),
        );
    }

    public function testDecryptWithInvalidBase64CiphertextThrowsException(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate ciphertext');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            '!!!invalid-base64!!!' . "\0" .
            \base64_encode('mac') . "\0" .
            \base64_encode('nonce'),
        );
    }

    public function testDecryptWithInvalidBase64MacThrowsException(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate message authentication code');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            \base64_encode('ciphertext') . "\0" .
            '!!!invalid-base64!!!' . "\0" .
            \base64_encode('nonce'),
        );
    }

    public function testDecryptWithInvalidBase64NonceThrowsException(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate nonce');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            \base64_encode('ciphertext') . "\0" .
            \base64_encode('mac') . "\0" .
            '!!!invalid-base64!!!',
        );
    }

    public function testFixedEncryptorNonceIsDeterministicForSameInput(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $plaintext = 'deterministic-nonce';

        $firstEncrypted = $aes256FixedEncryptor->encrypt($plaintext);
        $secondEncrypted = $aes256FixedEncryptor->encrypt($plaintext);

        $firstNonce = \explode("\0", $firstEncrypted)[5];
        $secondNonce = \explode("\0", $secondEncrypted)[5];

        static::assertSame($firstNonce, $secondNonce, 'Nonce must be deterministic for the same input');
    }

    public function testFixedEncryptorNonceDiffersForDifferentInputs(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        $firstEncrypted = $aes256FixedEncryptor->encrypt('input-a');
        $secondEncrypted = $aes256FixedEncryptor->encrypt('input-b');

        $firstNonce = \explode("\0", $firstEncrypted)[5];
        $secondNonce = \explode("\0", $secondEncrypted)[5];

        static::assertNotSame($firstNonce, $secondNonce, 'Nonce must differ for different inputs');
    }

    public function testFixedEncryptorNonceDoesNotLeakPlaintext(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $plaintext = 'secret-value-do-not-leak';

        $encrypted = $aes256FixedEncryptor->encrypt($plaintext);
        $rawNonce = \base64_decode(\explode("\0", $encrypted)[5], true);

        static::assertStringNotContainsString($plaintext, $rawNonce);
        static::assertStringNotContainsString($plaintext, \bin2hex($rawNonce));
    }

    public function testFixedEncryptorNonceLengthMatchesCipherIvLength(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $encrypted = $aes256FixedEncryptor->encrypt('nonce-length-test');

        $rawNonce = \base64_decode(\explode("\0", $encrypted)[5], true);
        $expectedLength = \openssl_cipher_iv_length('AES-256-CTR');

        static::assertSame($expectedLength, \strlen($rawNonce));
    }

    public function testFixedEncryptorDifferentSaltsDifferentNonces(): void
    {
        $firstAes256FixedEncryptor = new Aes256FixedEncryptor(\str_repeat('x', 32));
        $secondAes256FixedEncryptor = new Aes256FixedEncryptor(\str_repeat('y', 32));

        $plaintext = 'same-input';
        $nonceA = \explode("\0", $firstAes256FixedEncryptor->encrypt($plaintext))[5];
        $nonceB = \explode("\0", $secondAes256FixedEncryptor->encrypt($plaintext))[5];

        static::assertNotSame($nonceA, $nonceB, 'Different salts must produce different nonces');
    }

    public function testRandomEncryptorNonceLengthMatchesCipherIvLength(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('random-nonce-length-test');

        $rawNonce = \base64_decode(\explode("\0", $encrypted)[5], true);
        $expectedLength = \openssl_cipher_iv_length('AES-256-CTR');

        static::assertSame($expectedLength, \strlen($rawNonce));
    }

    public function testRandomEncryptorProducesUniqueNonces(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $plaintext = 'unique-nonce-test';

        $nonces = [];

        for ($i = 0; $i < 50; ++$i) {
            $encrypted = $aes256Encryptor->encrypt($plaintext);
            $nonces[] = \explode("\0", $encrypted)[5];
        }

        static::assertCount(50, \array_unique($nonces));
    }

    #[DataProvider('dataProviderRoundTripValues')]
    public function testRoundTripWithVariousValues(string $value): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        static::assertSame($value, $aes256Encryptor->decrypt($aes256Encryptor->encrypt($value)));
    }

    #[DataProvider('dataProviderRoundTripValues')]
    public function testFixedRoundTripWithVariousValues(string $value): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        static::assertSame($value, $aes256FixedEncryptor->decrypt($aes256FixedEncryptor->encrypt($value)));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function dataProviderRoundTripValues(): array
    {
        return [
            'empty string' => [''],
            'single character' => ['x'],
            'unicode' => ["\xC3\xA9\xC3\xA0\xC3\xBC"],
            'null bytes' => ["foo\0bar\0baz"],
            'long string' => [\str_repeat('abcdefghij', 1000)],
            'json payload' => ['{"key":"value","nested":{"a":1}}'],
            'base64-like' => ['SGVsbG8gV29ybGQ='],
            'encryption marker lookalike' => ['<ENC>not-actually-encrypted'],
            'newlines and tabs' => ["line1\nline2\ttab"],
            'binary-safe' => [\random_bytes(256)],
        ];
    }

    public function testSaltExactlyMinimumLengthIsAccepted(): void
    {
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('z', 32));

        $encrypted = $aes256Encryptor->encrypt('boundary-test');
        $decrypted = $aes256Encryptor->decrypt($encrypted);

        static::assertSame('boundary-test', $decrypted);
    }

    public function testSaltOneBelowMinimumThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid encryption salt');

        new Aes256Encryptor(\str_repeat('z', 31));
    }

    public function testSaltLongerThanMinimumIsAccepted(): void
    {
        $aes256Encryptor = new Aes256Encryptor(\str_repeat('z', 128));

        $encrypted = $aes256Encryptor->encrypt('long-salt-test');
        $decrypted = $aes256Encryptor->decrypt($encrypted);

        static::assertSame('long-salt-test', $decrypted);
    }

    public function testEncryptProducesV1Format(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('v1-format-test');

        $parts = \explode("\0", $encrypted);

        static::assertCount(6, $parts);
        static::assertSame(AbstractEncryptor::ENCRYPTION_MARKER, $parts[0]);
        static::assertSame(AbstractEncryptor::FORMAT_VERSION_V1, $parts[1]);
        static::assertSame(AbstractEncryptor::DEFAULT_SALT_VERSION, $parts[2]);
    }

    public function testDecryptReadsLegacyFourPartFormat(): void
    {
        $plaintext = 'legacy-roundtrip';
        $legacyCiphertext = self::produceLegacyCiphertext(self::SALT, $plaintext);

        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        static::assertSame($plaintext, $aes256Encryptor->decrypt($legacyCiphertext));
    }

    public function testTamperedLegacyMacRejected(): void
    {
        $legacyCiphertext = self::produceLegacyCiphertext(self::SALT, 'legacy-tamper');

        $parts = \explode("\0", $legacyCiphertext);
        $parts[2] = \base64_encode(\random_bytes(32));
        $tampered = \implode("\0", $parts);

        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testCanonicalHmacUsesLengthPrefixes(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('canonical-hmac-test');

        [, $version, $saltVersion, $base64Ciphertext, $base64Mac, $base64Nonce] = \explode("\0", $encrypted);

        $ciphertext = \base64_decode($base64Ciphertext, true);
        $mac = \base64_decode($base64Mac, true);
        $nonce = \base64_decode($base64Nonce, true);
        \assert(false !== $ciphertext);
        \assert(false !== $mac);
        \assert(false !== $nonce);

        $algorithm = 'AES-256-CTR';
        $macKey = \hash_hkdf('sha256', self::SALT, 32, 'authentication');

        $canonical = \pack('N', \strlen($version)) . $version
            . \pack('N', \strlen($saltVersion)) . $saltVersion
            . \pack('N', \strlen($algorithm)) . $algorithm
            . \pack('N', \strlen($ciphertext)) . $ciphertext
            . \pack('N', \strlen($nonce)) . $nonce;

        $expected = \hash_hmac('sha256', $canonical, $macKey, true);

        static::assertSame(true, \hash_equals($expected, $mac));
    }

    public function testEncryptOfAlreadyEncryptedLegacyPassesThrough(): void
    {
        $legacyCiphertext = self::produceLegacyCiphertext(self::SALT, 'passthrough-legacy');

        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        static::assertSame($legacyCiphertext, $aes256Encryptor->encrypt($legacyCiphertext));
    }

    public function testEncryptOfAlreadyEncryptedV1PassesThrough(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('passthrough-v1');

        static::assertSame($encrypted, $aes256Encryptor->encrypt($encrypted));
    }

    public function testAes256AndAes256FixedCanDecryptEachOther(): void
    {
        $salt = self::SALT;
        $aes256Encryptor = new Aes256Encryptor($salt);
        $aes256FixedEncryptor = new Aes256FixedEncryptor($salt);

        $plaintext = 'cross-test';

        /** @info same salt + algorithm = same derived keys, so cross-decryption succeeds */
        $encryptedByFixed = $aes256FixedEncryptor->encrypt($plaintext);
        $decryptedByRandom = $aes256Encryptor->decrypt($encryptedByFixed);

        static::assertSame($plaintext, $decryptedByRandom);
    }

    /** @info builds a pre-v4.0.0 (4-part, non-versioned) ciphertext using the legacy HMAC layout to verify backward-compatible decryption */
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
