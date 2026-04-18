<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;

abstract class AbstractEncryptor implements EncryptorInterface
{
    public const ENCRYPTION_MARKER = '<ENC>';
    public const GLUE = "\0";

    protected const ALGORITHM = 'AES-256-CTR';
    protected const HASH_ALGORITHM = 'sha256';
    protected const MINIMUM_KEY_LENGTH = 32;

    protected readonly string $nonceKey;
    private readonly string $encryptionKey;
    private readonly string $macKey;
    /** @var int<1, max>|null */
    private ?int $initialVectorLengthCache = null;

    abstract public function getTypeClass(): string;

    abstract protected function generateNonce(string $data): string;

    public function __construct(
        #[\SensitiveParameter]
        protected readonly string $salt,
    ) {
        if (\strlen($salt) < static::MINIMUM_KEY_LENGTH) {
            throw new Exception('invalid encryption salt');
        }

        $this->encryptionKey = $this->deriveKey($salt, 'encryption');
        $this->macKey = $this->deriveKey($salt, 'authentication');
        $this->nonceKey = $this->deriveKey($salt, 'nonce');
    }

    public function __debugInfo(): array
    {
        return ['algorithm' => static::ALGORITHM];
    }

    public function getTypeName(): string
    {
        $typeClass = $this->getTypeClass();

        if (false === \is_a($typeClass, AbstractType::class, true)) {
            throw new Exception('invalid encryption type class');
        }

        /** @var class-string<AbstractType> $typeClass */
        return $typeClass::getFullName();
    }

    public function encrypt(string $data): string
    {
        if (true === \str_starts_with($data, self::ENCRYPTION_MARKER . static::GLUE)) {
            $encryptedParts = \explode(static::GLUE, $data);

            if (4 === \count($encryptedParts)
                && false !== \base64_decode($encryptedParts[1], true)
                && false !== \base64_decode($encryptedParts[2], true)
                && false !== \base64_decode($encryptedParts[3], true)
            ) {
                return $data;
            }
        }

        $nonce = $this->generateNonce($data);

        $ciphertext = \openssl_encrypt(
            $data,
            static::ALGORITHM,
            $this->encryptionKey,
            \OPENSSL_RAW_DATA,
            $nonce,
        );

        if (false === $ciphertext) {
            throw new Exception('could not encrypt plaintext');
        }

        $messageAuthenticationCode = \hash_hmac(static::HASH_ALGORITHM, static::ALGORITHM . $ciphertext . $nonce, $this->macKey, true);

        return \implode(
            static::GLUE,
            [
                self::ENCRYPTION_MARKER,
                \base64_encode($ciphertext),
                \base64_encode($messageAuthenticationCode),
                \base64_encode($nonce),
            ],
        );
    }

    public function decrypt(string $data): string
    {
        if (false === \str_starts_with($data, self::ENCRYPTION_MARKER . static::GLUE)) {
            return $data;
        }

        $encryptedParts = \explode(static::GLUE, $data);

        if (4 !== \count($encryptedParts)) {
            throw new Exception('could not validate ciphertext');
        }

        [, $ciphertext, $messageAuthenticationCode, $nonce] = $encryptedParts;

        if (false === ($ciphertext = \base64_decode($ciphertext, true))) {
            throw new Exception('could not validate ciphertext');
        }

        if (false === ($messageAuthenticationCode = \base64_decode($messageAuthenticationCode, true))) {
            throw new Exception('could not validate message authentication code');
        }

        if (false === ($nonce = \base64_decode($nonce, true))) {
            throw new Exception('could not validate nonce');
        }

        $expected = \hash_hmac(static::HASH_ALGORITHM, static::ALGORITHM . $ciphertext . $nonce, $this->macKey, true);

        if (false === \hash_equals($expected, $messageAuthenticationCode)) {
            throw new Exception('invalid message authentication code');
        }

        $plaintext = \openssl_decrypt(
            $ciphertext,
            static::ALGORITHM,
            $this->encryptionKey,
            \OPENSSL_RAW_DATA,
            $nonce,
        );

        if (false === $plaintext) {
            throw new Exception('could not decrypt ciphertext');
        }

        return $plaintext;
    }

    /** @return int<1, max> */
    protected function getInitialVectorLength(): int
    {
        if (null !== $this->initialVectorLengthCache) {
            return $this->initialVectorLengthCache;
        }

        $initialVectorLength = \openssl_cipher_iv_length(static::ALGORITHM);

        if (false === $initialVectorLength || $initialVectorLength <= 0) {
            throw new Exception(\sprintf('failed to get IV length for cipher "%s"', static::ALGORITHM));
        }

        return $this->initialVectorLengthCache = $initialVectorLength;
    }

    protected function deriveKey(string $salt, string $information): string
    {
        return \hash_hkdf('sha256', $salt, 32, $information);
    }
}
