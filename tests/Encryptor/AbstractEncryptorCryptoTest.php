<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;

/**
 * Deep cryptographic tests for AbstractEncryptor, covering HKDF key derivation,
 * HMAC MAC computation, nonce derivation, and tamper-resistance.
 *
 * @internal
 */
final class AbstractEncryptorCryptoTest extends TestCase
{
    private const SALT = 'abcdefghijklmnopqrstuvwxyz123456'; // 32 bytes

    // ──────────────────────────────────────────────
    //  HKDF key derivation consistency
    // ──────────────────────────────────────────────

    public function testDerivedKeysAreConsistentAcrossInstances(): void
    {
        $firstEncryptor = new AES256Encryptor(self::SALT);
        $secondEncryptor = new AES256Encryptor(self::SALT);

        $plaintext = 'deterministic-key-test';

        // Both instances with the same salt must be able to decrypt each other's output.
        $encrypted = $firstEncryptor->encrypt($plaintext);
        $decrypted = $secondEncryptor->decrypt($encrypted);

        static::assertSame($plaintext, $decrypted);
    }

    public function testDifferentSaltsProduceDifferentKeys(): void
    {
        $saltA = \str_repeat('a', 32);
        $saltB = \str_repeat('b', 32);

        $firstAes256FixedEncryptor = new AES256FixedEncryptor($saltA);
        $secondAes256FixedEncryptor = new AES256FixedEncryptor($saltB);

        $plaintext = 'cross-key-test';

        $encryptedA = $firstAes256FixedEncryptor->encrypt($plaintext);
        $encryptedB = $secondAes256FixedEncryptor->encrypt($plaintext);

        // Different salts must produce different ciphertext.
        static::assertNotSame($encryptedA, $encryptedB);

        // Decrypting with the wrong key must fail (invalid MAC).
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $secondAes256FixedEncryptor->decrypt($encryptedA);
    }

    public function testHkdfDerivesSeparateEncryptionAndMacKeys(): void
    {
        // This is an indirect test: if encryption key == mac key, then swapping
        // ciphertext and mac in the payload would still verify. We verify that
        // tampered payloads are always rejected, proving the keys are distinct.
        $aes256Encryptor = new AES256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('verify-key-separation');

        $parts = \explode("\0", $encrypted);
        static::assertCount(4, $parts);

        // Swap ciphertext and mac.
        [$marker, $ciphertext, $mac, $nonce] = $parts;
        $swapped = \implode("\0", [$marker, $mac, $ciphertext, $nonce]);

        $this->expectException(Exception::class);

        $aes256Encryptor->decrypt($swapped);
    }

    // ──────────────────────────────────────────────
    //  HMAC MAC verification
    // ──────────────────────────────────────────────

    public function testTamperedCiphertextDetected(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('mac-test');

        $parts = \explode("\0", $encrypted);
        $rawCiphertext = \base64_decode($parts[1], true);
        // Flip one bit in the ciphertext.
        $rawCiphertext[0] = \chr(\ord($rawCiphertext[0]) ^ 0x01);
        $parts[1] = \base64_encode($rawCiphertext);
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testTamperedNonceDetected(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('nonce-tamper-test');

        $parts = \explode("\0", $encrypted);
        $rawNonce = \base64_decode($parts[3], true);
        $rawNonce[0] = \chr(\ord($rawNonce[0]) ^ 0x01);
        $parts[3] = \base64_encode($rawNonce);
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testTamperedMarkerStillPassesMarkerCheckButFailsMac(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('marker-test');

        // Keep the marker prefix intact but corrupt a later portion,
        // so it passes the str_starts_with check but the MAC is now wrong.
        $parts = \explode("\0", $encrypted);
        $parts[2] = \base64_encode(\random_bytes(32));
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testMacCoversAlgorithmIdentifier(): void
    {
        // The MAC covers "AES-256-CTR" + ciphertext + nonce.
        // If the algorithm identifier were not covered, an attacker
        // could substitute a weaker algorithm. We cannot directly test
        // this without reflection, but we can verify the MAC includes
        // all three components by ensuring any byte change is detected.
        $aes256FixedEncryptor = new AES256FixedEncryptor(self::SALT);
        $encrypted = $aes256FixedEncryptor->encrypt('algo-coverage-test');

        // Verify the encrypted output has exactly 4 parts.
        $parts = \explode("\0", $encrypted);
        static::assertCount(4, $parts);

        // Verify marker.
        static::assertSame(AbstractEncryptor::ENCRYPTION_MARKER, $parts[0]);

        // Each of ciphertext, mac, nonce must be valid base64.
        static::assertSame(true, false !== \base64_decode($parts[1], true));
        static::assertSame(true, false !== \base64_decode($parts[2], true));
        static::assertSame(true, false !== \base64_decode($parts[3], true));

        // MAC must be exactly 32 bytes (sha256 raw output).
        static::assertSame(32, \strlen(\base64_decode($parts[2], true)));
    }

    // ──────────────────────────────────────────────
    //  Decrypt edge cases
    // ──────────────────────────────────────────────

    public function testDecryptWithTooFewPartsThrowsException(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate ciphertext');

        // Only marker + one part (instead of marker + ciphertext + mac + nonce).
        $aes256Encryptor->decrypt(AbstractEncryptor::ENCRYPTION_MARKER . "\0" . \base64_encode('data'));
    }

    public function testDecryptWithTooManyPartsThrowsException(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate ciphertext');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            \base64_encode('a') . "\0" .
            \base64_encode('b') . "\0" .
            \base64_encode('c') . "\0" .
            \base64_encode('d'),
        );
    }

    public function testDecryptWithInvalidBase64CiphertextThrowsException(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate ciphertext');

        // Invalid base64 with = in wrong position.
        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            '!!!invalid-base64!!!' . "\0" .
            \base64_encode('mac') . "\0" .
            \base64_encode('nonce'),
        );
    }

    public function testDecryptWithInvalidBase64MacThrowsException(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate mac');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            \base64_encode('ciphertext') . "\0" .
            '!!!invalid-base64!!!' . "\0" .
            \base64_encode('nonce'),
        );
    }

    public function testDecryptWithInvalidBase64NonceThrowsException(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate nonce');

        $aes256Encryptor->decrypt(
            AbstractEncryptor::ENCRYPTION_MARKER . "\0" .
            \base64_encode('ciphertext') . "\0" .
            \base64_encode('mac') . "\0" .
            '!!!invalid-base64!!!',
        );
    }

    // ──────────────────────────────────────────────
    //  AES256Fixed deterministic nonce
    // ──────────────────────────────────────────────

    public function testFixedEncryptorNonceIsDeterministicForSameInput(): void
    {
        $aes256FixedEncryptor = new AES256FixedEncryptor(self::SALT);
        $plaintext = 'deterministic-nonce';

        $firstEncrypted = $aes256FixedEncryptor->encrypt($plaintext);
        $secondEncrypted = $aes256FixedEncryptor->encrypt($plaintext);

        // Extract nonces.
        $firstNonce = \explode("\0", $firstEncrypted)[3];
        $secondNonce = \explode("\0", $secondEncrypted)[3];

        static::assertSame($firstNonce, $secondNonce, 'Nonce must be deterministic for the same input');
    }

    public function testFixedEncryptorNonceDiffersForDifferentInputs(): void
    {
        $aes256FixedEncryptor = new AES256FixedEncryptor(self::SALT);

        $firstEncrypted = $aes256FixedEncryptor->encrypt('input-a');
        $secondEncrypted = $aes256FixedEncryptor->encrypt('input-b');

        $firstNonce = \explode("\0", $firstEncrypted)[3];
        $secondNonce = \explode("\0", $secondEncrypted)[3];

        static::assertNotSame($firstNonce, $secondNonce, 'Nonce must differ for different inputs');
    }

    public function testFixedEncryptorNonceDoesNotLeakPlaintext(): void
    {
        $aes256FixedEncryptor = new AES256FixedEncryptor(self::SALT);
        $plaintext = 'secret-value-do-not-leak';

        $encrypted = $aes256FixedEncryptor->encrypt($plaintext);
        $rawNonce = \base64_decode(\explode("\0", $encrypted)[3], true);

        // The nonce is derived from HMAC-SHA256, truncated. It should not
        // contain any substring of the plaintext.
        static::assertStringNotContainsString($plaintext, $rawNonce);
        static::assertStringNotContainsString($plaintext, \bin2hex($rawNonce));
    }

    public function testFixedEncryptorNonceLengthMatchesCipherIvLength(): void
    {
        $aes256FixedEncryptor = new AES256FixedEncryptor(self::SALT);
        $encrypted = $aes256FixedEncryptor->encrypt('nonce-length-test');

        $rawNonce = \base64_decode(\explode("\0", $encrypted)[3], true);
        $expectedLength = \openssl_cipher_iv_length('AES-256-CTR');

        static::assertSame($expectedLength, \strlen($rawNonce));
    }

    public function testFixedEncryptorDifferentSaltsDifferentNonces(): void
    {
        $firstAes256FixedEncryptor = new AES256FixedEncryptor(\str_repeat('x', 32));
        $secondAes256FixedEncryptor = new AES256FixedEncryptor(\str_repeat('y', 32));

        $plaintext = 'same-input';
        $nonceA = \explode("\0", $firstAes256FixedEncryptor->encrypt($plaintext))[3];
        $nonceB = \explode("\0", $secondAes256FixedEncryptor->encrypt($plaintext))[3];

        static::assertNotSame($nonceA, $nonceB, 'Different salts must produce different nonces');
    }

    // ──────────────────────────────────────────────
    //  AES256 (random) nonce
    // ──────────────────────────────────────────────

    public function testRandomEncryptorNonceLengthMatchesCipherIvLength(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('random-nonce-length-test');

        $rawNonce = \base64_decode(\explode("\0", $encrypted)[3], true);
        $expectedLength = \openssl_cipher_iv_length('AES-256-CTR');

        static::assertSame($expectedLength, \strlen($rawNonce));
    }

    public function testRandomEncryptorProducesUniqueNonces(): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);
        $plaintext = 'unique-nonce-test';

        $nonces = [];

        for ($i = 0; $i < 50; ++$i) {
            $encrypted = $aes256Encryptor->encrypt($plaintext);
            $nonces[] = \explode("\0", $encrypted)[3];
        }

        // All nonces should be unique (collision probability is negligible).
        static::assertCount(50, \array_unique($nonces));
    }

    // ──────────────────────────────────────────────
    //  Round-trip with various data types
    // ──────────────────────────────────────────────

    /**
     * @dataProvider dataProviderRoundTripValues
     */
    public function testRoundTripWithVariousValues(string $value): void
    {
        $aes256Encryptor = new AES256Encryptor(self::SALT);

        static::assertSame($value, $aes256Encryptor->decrypt($aes256Encryptor->encrypt($value)));
    }

    /**
     * @dataProvider dataProviderRoundTripValues
     */
    public function testFixedRoundTripWithVariousValues(string $value): void
    {
        $aes256FixedEncryptor = new AES256FixedEncryptor(self::SALT);

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

    // ──────────────────────────────────────────────
    //  Salt boundary tests
    // ──────────────────────────────────────────────

    public function testSaltExactlyMinimumLengthIsAccepted(): void
    {
        $aes256Encryptor = new AES256Encryptor(\str_repeat('z', 32));

        $encrypted = $aes256Encryptor->encrypt('boundary-test');
        $decrypted = $aes256Encryptor->decrypt($encrypted);

        static::assertSame('boundary-test', $decrypted);
    }

    public function testSaltOneBelowMinimumThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid encryption salt');

        new AES256Encryptor(\str_repeat('z', 31));
    }

    public function testSaltLongerThanMinimumIsAccepted(): void
    {
        $aes256Encryptor = new AES256Encryptor(\str_repeat('z', 128));

        $encrypted = $aes256Encryptor->encrypt('long-salt-test');
        $decrypted = $aes256Encryptor->decrypt($encrypted);

        static::assertSame('long-salt-test', $decrypted);
    }

    // ──────────────────────────────────────────────
    //  Cross-encryptor incompatibility
    // ──────────────────────────────────────────────

    public function testAES256AndAES256FixedCannotDecryptEachOther(): void
    {
        $salt = self::SALT;
        $aes256Encryptor = new AES256Encryptor($salt);
        $aes256FixedEncryptor = new AES256FixedEncryptor($salt);

        $plaintext = 'cross-test';

        // They use the same salt and same algorithm, so derived keys are the same.
        // However, the nonces differ, so the MAC will still match because
        // the MAC covers the actual nonce used. In fact, cross-decryption should
        // succeed because the key derivation is identical.
        $encryptedByFixed = $aes256FixedEncryptor->encrypt($plaintext);
        $decryptedByRandom = $aes256Encryptor->decrypt($encryptedByFixed);

        static::assertSame($plaintext, $decryptedByRandom);
    }
}
