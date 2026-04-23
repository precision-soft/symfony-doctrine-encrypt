<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\StringType;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;

abstract class AbstractType extends StringType
{
    protected const DEFAULT_LENGTH = 1000;

    private ?EncryptorInterface $encryptor = null;

    abstract protected static function getShortName(): string;

    public static function getFullName(): string
    {
        return 'encrypted' . static::getShortName();
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        if (false === isset($column['length'])) {
            $column['length'] = static::DEFAULT_LENGTH;
        }

        return parent::getSQLDeclaration($column, $platform);
    }

    public function getEncryptor(): EncryptorInterface
    {
        $this->validate();

        \assert(null !== $this->encryptor);

        return $this->encryptor;
    }

    public function setEncryptor(EncryptorInterface $encryptor): self
    {
        $this->encryptor = $encryptor;

        return $this;
    }

    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (null === $value) {
            return null;
        }

        if (false === \is_string($value)) {
            throw new Exception(\sprintf('expected string value for encryption, got `%s`', \get_debug_type($value)));
        }

        return $this->getEncryptor()->encrypt($value);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?string
    {
        if (null === $value) {
            return null;
        }

        if (false === \is_string($value)) {
            throw new Exception(\sprintf('expected string value for decryption, got `%s`', \get_debug_type($value)));
        }

        return $this->getEncryptor()->decrypt($value);
    }

    protected function validate(): void
    {
        if (null === $this->encryptor) {
            throw new Exception('the encryptor was not set');
        }
    }
}
