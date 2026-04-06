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

    protected const ALGORITHM = 'AES-256-CTR';
    protected const HASH_ALGORITHM = 'sha256';
    protected const MINIMUM_KEY_LENGTH = 32;
    protected const GLUE = "\0";

    private readonly string $encryptionKey;

    private readonly string $macKey;

    protected readonly string $nonceKey;

    abstract public function getTypeClass(): ?string;

    abstract protected function generateNonce(string $data): string;

    public function __construct(
        #[\SensitiveParameter]
        protected readonly string $salt,
    ) {
        if (\strlen($salt) < static::MINIMUM_KEY_LENGTH) {
            throw new Exception('invalid encryption salt');
        }

        $this->encryptionKey = self::deriveKey($salt, 'encryption');
        $this->macKey = self::deriveKey($salt, 'authentication');
        $this->nonceKey = self::deriveKey($salt, 'nonce');
    }

    private static function deriveKey(string $salt, string $info): string
    {
        return \hash_hkdf('sha256', $salt, 32, $info);
    }

    final public function getTypeName(): ?string
    {
        $typeClass = $this->getTypeClass();

        if (null === $typeClass) {
            return null;
        }

        /** @var class-string<AbstractType> $typeClass */
        if (false === \is_a($typeClass, AbstractType::class, true)) {
            throw new Exception('invalid encryption type class');
        }

        return $typeClass::getFullName();
    }

    public function encrypt(string $data): string
    {
        if (true === \str_starts_with($data, self::ENCRYPTION_MARKER . static::GLUE)) {
            return $data;
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

        $mac = \hash_hmac(static::HASH_ALGORITHM, static::ALGORITHM . $ciphertext . $nonce, $this->macKey, true);

        return \implode(
            static::GLUE,
            [
                self::ENCRYPTION_MARKER,
                \base64_encode($ciphertext),
                \base64_encode($mac),
                \base64_encode($nonce),
            ],
        );
    }

    public function decrypt(string $data): string
    {
        if (false === \str_starts_with($data, self::ENCRYPTION_MARKER . static::GLUE)) {
            return $data;
        }

        $parts = \explode(static::GLUE, $data);

        if (4 !== \count($parts)) {
            throw new Exception('could not validate ciphertext');
        }

        [, $ciphertext, $mac, $nonce] = $parts;

        if (false === ($ciphertext = \base64_decode($ciphertext, true))) {
            throw new Exception('could not validate ciphertext');
        }

        if (false === ($mac = \base64_decode($mac, true))) {
            throw new Exception('could not validate mac');
        }

        if (false === ($nonce = \base64_decode($nonce, true))) {
            throw new Exception('could not validate nonce');
        }

        $expected = \hash_hmac(static::HASH_ALGORITHM, static::ALGORITHM . $ciphertext . $nonce, $this->macKey, true);

        if (false === \hash_equals($expected, $mac)) {
            throw new Exception('invalid mac');
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
}
