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
use Throwable;

/**
 * The contract is deliberately weaker than "always throws": a mutation that destroys the `<ENC>\0` prefix legitimately makes `decrypt()` a pass-through. The plaintext must never come back out.
 *
 * @internal
 */
final class AbstractEncryptorTamperTest extends TestCase
{
    private const SALT = 'abcdefghijklmnopqrstuvwxyz123456';
    private const OTHER_SALT = '6543210zyxwvutsrqponmlkjihgfedcba';
    private const PLAINTEXT = 'tamper-matrix-subject';

    /** @return iterable<string, array{int}> */
    public static function dataProviderBitFlipOffset(): iterable
    {
        $length = \strlen(self::buildPayload());

        for ($offset = 0; $offset < $length; ++$offset) {
            yield 'offset ' . $offset => [$offset];
        }
    }

    /** @return iterable<string, array{int}> */
    public static function dataProviderTruncationLength(): iterable
    {
        $length = \strlen(self::buildPayload());

        for ($truncatedLength = 0; $truncatedLength < $length; ++$truncatedLength) {
            yield 'length ' . $truncatedLength => [$truncatedLength];
        }
    }

    #[DataProvider('dataProviderBitFlipOffset')]
    public function testSingleBitFlipNeverYieldsThePlaintext(int $offset): void
    {
        $payload = self::buildPayload();
        $payload[$offset] = \chr(\ord($payload[$offset]) ^ 0x01);

        $this->assertNeverReturnsPlaintext($payload);
    }

    /* removing trailing base64 padding is the one truncation that legitimately survives, since it encodes the same bytes */
    #[DataProvider('dataProviderTruncationLength')]
    public function testTruncationNeverYieldsThePlaintext(int $truncatedLength): void
    {
        $payload = self::buildPayload();
        $truncated = \substr($payload, 0, $truncatedLength);
        $removed = \substr($payload, $truncatedLength);

        if ('' !== $removed && $removed === \str_repeat('=', \strlen($removed)) && true === self::hasDecodableTail($truncated)) {
            static::assertSame(self::PLAINTEXT, (new Aes256FixedEncryptor(self::SALT))->decrypt($truncated));

            return;
        }

        $this->assertNeverReturnsPlaintext($truncated);
    }

    /* the extra byte lands in the nonce segment, so strict base64 rejects it before the MAC is ever computed */
    public function testAppendedByteIsRejected(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('could not validate nonce');

        $aes256FixedEncryptor->decrypt(self::buildPayload() . 'x');
    }

    public function testUnpaddedEnvelopeAuthenticatesIdentically(): void
    {
        $aes256FixedEncryptor = new Aes256FixedEncryptor(self::SALT);

        $parts = \explode(AbstractEncryptor::GLUE, self::buildPayload());
        $unpadded = \implode(
            AbstractEncryptor::GLUE,
            [
                $parts[0],
                $parts[1],
                $parts[2],
                \rtrim($parts[3], '='),
                \rtrim($parts[4], '='),
                \rtrim($parts[5], '='),
            ],
        );

        static::assertNotSame(self::buildPayload(), $unpadded);
        static::assertSame(self::PLAINTEXT, $aes256FixedEncryptor->decrypt($unpadded));
    }

    public function testNonceSwappedBetweenTwoCiphertextsOfTheSameKeyIsRejected(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $firstParts = \explode(AbstractEncryptor::GLUE, $aes256Encryptor->encrypt('first-subject'));
        $secondParts = \explode(AbstractEncryptor::GLUE, $aes256Encryptor->encrypt('second-subject'));

        $firstParts[5] = $secondParts[5];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt(\implode(AbstractEncryptor::GLUE, $firstParts));
    }

    public function testSaltVersionSegmentCannotBeRepointedAtAnotherEpoch(): void
    {
        $aes256Encryptor = new Aes256Encryptor(
            ['v1' => self::SALT, 'v2' => self::OTHER_SALT],
            'v1',
        );

        $parts = \explode(AbstractEncryptor::GLUE, $aes256Encryptor->encrypt(self::PLAINTEXT));
        static::assertSame('v1', $parts[2]);

        $parts[2] = 'v2';

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt(\implode(AbstractEncryptor::GLUE, $parts));
    }

    public function testUnknownSaltVersionSegmentIsRejectedBeforeAnyCryptography(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $parts = \explode(AbstractEncryptor::GLUE, $aes256Encryptor->encrypt(self::PLAINTEXT));
        $parts[2] = 'no-such-version';

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('unknown salt version `no-such-version`');

        $aes256Encryptor->decrypt(\implode(AbstractEncryptor::GLUE, $parts));
    }

    /** @return iterable<string, array{string}> */
    public static function dataProviderForgedFormatVersion(): iterable
    {
        yield 'future version' => ['v2'];
        yield 'empty version' => [''];
        yield 'legacy-looking version' => ['v0'];
    }

    #[DataProvider('dataProviderForgedFormatVersion')]
    public function testForgedFormatVersionIsRejected(string $formatVersion): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $parts = \explode(AbstractEncryptor::GLUE, $aes256Encryptor->encrypt(self::PLAINTEXT));
        $parts[1] = $formatVersion;

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt(\implode(AbstractEncryptor::GLUE, $parts));
    }

    public function testV1PayloadCannotBeDowngradedToTheLegacyFourPartShape(): void
    {
        $aes256Encryptor = new Aes256Encryptor(self::SALT);

        $parts = \explode(AbstractEncryptor::GLUE, $aes256Encryptor->encrypt(self::PLAINTEXT));
        $downgraded = \implode(AbstractEncryptor::GLUE, [$parts[0], $parts[3], $parts[4], $parts[5]]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('invalid message authentication code');

        $aes256Encryptor->decrypt($downgraded);
    }

    private function assertNeverReturnsPlaintext(string $payload): void
    {
        try {
            $decrypted = (new Aes256FixedEncryptor(self::SALT))->decrypt($payload);
        } catch (Exception $exception) {
            static::assertNotSame('', $exception->getMessage());

            return;
        } catch (Throwable $throwable) {
            static::fail(\sprintf(
                'decrypt() escaped a non-bundle throwable: %s: %s',
                $throwable::class,
                $throwable->getMessage(),
            ));
        }

        static::assertNotSame(self::PLAINTEXT, $decrypted);
    }

    /* dropping only part of the padding leaves a length strict base64 rejects, so the equivalence holds for full removal alone */
    private static function hasDecodableTail(string $payload): bool
    {
        $lastGlue = \strrpos($payload, AbstractEncryptor::GLUE);

        if (false === $lastGlue) {
            return false;
        }

        return false !== \base64_decode(\substr($payload, $lastGlue + 1), true);
    }

    private static function buildPayload(): string
    {
        return (new Aes256FixedEncryptor(self::SALT))->encrypt(self::PLAINTEXT);
    }
}
