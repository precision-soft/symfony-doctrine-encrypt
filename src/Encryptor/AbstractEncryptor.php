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
    public const FORMAT_VERSION_V1 = 'v1';
    public const DEFAULT_SALT_VERSION = 'default';

    protected const ALGORITHM = 'AES-256-CTR';
    protected const HASH_ALGORITHM = 'sha256';
    protected const MINIMUM_KEY_LENGTH = 32;
    protected const CURRENT_FORMAT_VERSION = self::FORMAT_VERSION_V1;

    protected readonly string $currentSaltVersion;
    protected readonly string $nonceKey;
    /** @var array<string, string> */
    private readonly array $encryptionKeysBySaltVersion;
    /** @var array<string, string> */
    private readonly array $macKeysBySaltVersion;
    /** @var int<1, max>|null */
    private ?int $initialVectorLengthCache = null;

    abstract public function getTypeClass(): string;

    abstract protected function generateNonce(string $data): string;

    /** @param array<string, string>|string $saltsByVersion a bare string is treated as a one-entry map keyed by `DEFAULT_SALT_VERSION` for BC with the single-salt setup */
    public function __construct(
        #[\SensitiveParameter]
        array|string $saltsByVersion,
        string $currentSaltVersion = self::DEFAULT_SALT_VERSION,
    ) {
        if (true === \is_string($saltsByVersion)) {
            $saltsByVersion = [self::DEFAULT_SALT_VERSION => $saltsByVersion];
        }

        if ([] === $saltsByVersion) {
            throw new Exception('at least one salt is required');
        }

        if (false === \array_key_exists($currentSaltVersion, $saltsByVersion)) {
            throw new Exception(\sprintf('current salt version `%s` not present in salts map', $currentSaltVersion));
        }

        $encryptionKeys = [];
        $macKeys = [];
        $nonceKeys = [];

        foreach ($saltsByVersion as $saltVersion => $salt) {
            if (\strlen($salt) < static::MINIMUM_KEY_LENGTH) {
                throw new Exception(\sprintf('invalid encryption salt for version `%s`', $saltVersion));
            }

            $encryptionKeys[$saltVersion] = $this->deriveKey($salt, 'encryption');
            $macKeys[$saltVersion] = $this->deriveKey($salt, 'authentication');
            $nonceKeys[$saltVersion] = $this->deriveKey($salt, 'nonce');
        }

        $this->encryptionKeysBySaltVersion = $encryptionKeys;
        $this->macKeysBySaltVersion = $macKeys;
        $this->currentSaltVersion = $currentSaltVersion;
        $this->nonceKey = $nonceKeys[$currentSaltVersion];
    }

    public function __debugInfo(): array
    {
        return [
            'algorithm' => static::ALGORITHM,
            'saltVersions' => \array_keys($this->encryptionKeysBySaltVersion),
            'currentSaltVersion' => $this->currentSaltVersion,
        ];
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
        if (true === $this->looksEncrypted($data)) {
            return $data;
        }

        $nonce = $this->generateNonce($data);

        $ciphertext = \openssl_encrypt(
            $data,
            static::ALGORITHM,
            $this->encryptionKeysBySaltVersion[$this->currentSaltVersion],
            \OPENSSL_RAW_DATA,
            $nonce,
        );

        if (false === $ciphertext) {
            throw new Exception('could not encrypt plaintext');
        }

        $messageAuthenticationCode = $this->computeMessageAuthenticationCode(
            static::CURRENT_FORMAT_VERSION,
            $this->currentSaltVersion,
            static::ALGORITHM,
            $ciphertext,
            $nonce,
            $this->macKeysBySaltVersion[$this->currentSaltVersion],
        );

        return \implode(
            static::GLUE,
            [
                self::ENCRYPTION_MARKER,
                static::CURRENT_FORMAT_VERSION,
                $this->currentSaltVersion,
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
        $partCount = \count($encryptedParts);

        if (6 === $partCount) {
            [, $formatVersion, $saltVersion, $ciphertext, $messageAuthenticationCode, $nonce] = $encryptedParts;
        } elseif (4 === $partCount) {
            $formatVersion = null;
            $saltVersion = $this->currentSaltVersion;
            [, $ciphertext, $messageAuthenticationCode, $nonce] = $encryptedParts;
        } else {
            throw new Exception('could not validate ciphertext');
        }

        if (false === \array_key_exists($saltVersion, $this->encryptionKeysBySaltVersion)) {
            throw new Exception(\sprintf('unknown salt version `%s`', $saltVersion));
        }

        if (false === ($ciphertext = \base64_decode($ciphertext, true))) {
            throw new Exception('could not validate ciphertext');
        }

        if (false === ($messageAuthenticationCode = \base64_decode($messageAuthenticationCode, true))) {
            throw new Exception('could not validate message authentication code');
        }

        if (false === ($nonce = \base64_decode($nonce, true))) {
            throw new Exception('could not validate nonce');
        }

        $macKey = $this->macKeysBySaltVersion[$saltVersion];

        $expected = null === $formatVersion
            ? $this->computeLegacyMessageAuthenticationCode(static::ALGORITHM, $ciphertext, $nonce, $macKey)
            : $this->computeMessageAuthenticationCode($formatVersion, $saltVersion, static::ALGORITHM, $ciphertext, $nonce, $macKey);

        if (false === \hash_equals($expected, $messageAuthenticationCode)) {
            throw new Exception('invalid message authentication code');
        }

        $plaintext = \openssl_decrypt(
            $ciphertext,
            static::ALGORITHM,
            $this->encryptionKeysBySaltVersion[$saltVersion],
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

    /** @info canonical length-prefixed HMAC input prevents ambiguity between concatenated fields of variable length */
    protected function computeMessageAuthenticationCode(
        string $formatVersion,
        string $saltVersion,
        string $algorithm,
        string $ciphertext,
        string $nonce,
        string $macKey,
    ): string {
        $canonical = \pack('N', \strlen($formatVersion)) . $formatVersion
            . \pack('N', \strlen($saltVersion)) . $saltVersion
            . \pack('N', \strlen($algorithm)) . $algorithm
            . \pack('N', \strlen($ciphertext)) . $ciphertext
            . \pack('N', \strlen($nonce)) . $nonce;

        return \hash_hmac(static::HASH_ALGORITHM, $canonical, $macKey, true);
    }

    /** @info legacy (pre-v1) HMAC over `algorithm . ciphertext . nonce` — kept for backward-compatible decryption of data written before v4.0.0 */
    protected function computeLegacyMessageAuthenticationCode(
        string $algorithm,
        string $ciphertext,
        string $nonce,
        string $macKey,
    ): string {
        return \hash_hmac(static::HASH_ALGORITHM, $algorithm . $ciphertext . $nonce, $macKey, true);
    }

    protected function looksEncrypted(string $data): bool
    {
        if (false === \str_starts_with($data, self::ENCRYPTION_MARKER . static::GLUE)) {
            return false;
        }

        $parts = \explode(static::GLUE, $data);
        $count = \count($parts);

        if (6 === $count) {
            return false !== \base64_decode($parts[3], true)
                && false !== \base64_decode($parts[4], true)
                && false !== \base64_decode($parts[5], true);
        }

        if (4 === $count) {
            return false !== \base64_decode($parts[1], true)
                && false !== \base64_decode($parts[2], true)
                && false !== \base64_decode($parts[3], true);
        }

        return false;
    }
}
