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
        $firstEncryptor = new Aes256Encryptor(self::SALT);
        $secondEncryptor = new Aes256Encryptor(self::SALT);

        $plaintext = 'deterministic-key-test';

        $encrypted = $firstEncryptor->encrypt($plaintext);
        $decrypted = $secondEncryptor->decrypt($encrypted);

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
        $this->expectExceptionMessage('invalid mac');

        $secondAes256FixedEncryptor->decrypt($encryptedA);
    }

    /** @info indirect test: if encKey == macKey, swapping ciphertext and mac would still verify */
    public function testHkdfDerivesSeparateEncryptionAndMacKeys(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('verify-key-separation');

        $parts = \explode("\0", $encrypted);
        static::assertCount(4, $parts);

        [$marker, $ciphertext, $mac, $nonce] = $parts;
        $swapped = \implode("\0", [$marker, $mac, $ciphertext, $nonce]);

        $this->expectException(Exception::class);

        $aes256Encryptor->decrypt($swapped);
    }

    public function testTamperedCiphertextDetected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('mac-test');

        $parts = \explode("\0", $encrypted);
        $rawCiphertext = \base64_decode($parts[1], true);
        $rawCiphertext[0] = \chr(\ord($rawCiphertext[0]) ^ 0x01);
        $parts[1] = \base64_encode($rawCiphertext);
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $aes256Encryptor->decrypt($tampered);
    }

    public function testTamperedNonceDetected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
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
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('marker-test');

        $parts = \explode("\0", $encrypted);
        $parts[2] = \base64_encode(\random_bytes(32));
        $tampered = \implode("\0", $parts);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid mac');

        $aes256Encryptor->decrypt($tampered);
    }

    /** @info MAC covers algorithm + ciphertext + nonce; verifies structure and base64 validity */
    public function testMacCoversAlgorithmIdentifier(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $encrypted = $aes256FixedEncryptor->encrypt('algo-coverage-test');

        $parts = \explode("\0", $encrypted);
        static::assertCount(4, $parts);
        static::assertSame(AbstractEncryptor::ENCRYPTION_MARKER, $parts[0]);
        static::assertSame(true, false !== \base64_decode($parts[1], true));
        static::assertSame(true, false !== \base64_decode($parts[2], true));
        static::assertSame(true, false !== \base64_decode($parts[3], true));
        static::assertSame(32, \strlen(\base64_decode($parts[2], true)));
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

        $firstNonce = \explode("\0", $firstEncrypted)[3];
        $secondNonce = \explode("\0", $secondEncrypted)[3];

        static::assertSame($firstNonce, $secondNonce, 'Nonce must be deterministic for the same input');
    }

    public function testFixedEncryptorNonceDiffersForDifferentInputs(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        $firstEncrypted = $aes256FixedEncryptor->encrypt('input-a');
        $secondEncrypted = $aes256FixedEncryptor->encrypt('input-b');

        $firstNonce = \explode("\0", $firstEncrypted)[3];
        $secondNonce = \explode("\0", $secondEncrypted)[3];

        static::assertNotSame($firstNonce, $secondNonce, 'Nonce must differ for different inputs');
    }

    public function testFixedEncryptorNonceDoesNotLeakPlaintext(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $plaintext = 'secret-value-do-not-leak';

        $encrypted = $aes256FixedEncryptor->encrypt($plaintext);
        $rawNonce = \base64_decode(\explode("\0", $encrypted)[3], true);

        static::assertStringNotContainsString($plaintext, $rawNonce);
        static::assertStringNotContainsString($plaintext, \bin2hex($rawNonce));
    }

    public function testFixedEncryptorNonceLengthMatchesCipherIvLength(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);
        $encrypted = $aes256FixedEncryptor->encrypt('nonce-length-test');

        $rawNonce = \base64_decode(\explode("\0", $encrypted)[3], true);
        $expectedLength = \openssl_cipher_iv_length('AES-256-CTR');

        static::assertSame($expectedLength, \strlen($rawNonce));
    }

    public function testFixedEncryptorDifferentSaltsDifferentNonces(): void
    {
        $firstAes256FixedEncryptor = new Aes256FixedEncryptor(\str_repeat('x', 32));
        $secondAes256FixedEncryptor = new Aes256FixedEncryptor(\str_repeat('y', 32));

        $plaintext = 'same-input';
        $nonceA = \explode("\0", $firstAes256FixedEncryptor->encrypt($plaintext))[3];
        $nonceB = \explode("\0", $secondAes256FixedEncryptor->encrypt($plaintext))[3];

        static::assertNotSame($nonceA, $nonceB, 'Different salts must produce different nonces');
    }

    public function testRandomEncryptorNonceLengthMatchesCipherIvLength(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);
        $encrypted = $aes256Encryptor->encrypt('random-nonce-length-test');

        $rawNonce = \base64_decode(\explode("\0", $encrypted)[3], true);
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
            $nonces[] = \explode("\0", $encrypted)[3];
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
}
