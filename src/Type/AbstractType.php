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
    private const DEFAULT_LENGTH = 1000;

    private EncryptorInterface $encryptor;

    abstract protected static function getShortName(): string;

    final public static function getFullName(): string
    {
        return 'encrypted' . static::getShortName();
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        if (false === isset($column['length']) || null === $column['length']) {
            $column['length'] = self::DEFAULT_LENGTH;
        }

        return parent::getSQLDeclaration($column, $platform);
    }

    final public function getEncryptor(): EncryptorInterface
    {
        $this->validate();

        return $this->encryptor;
    }

    final public function setEncryptor(EncryptorInterface $encryptor): self
    {
        $this->encryptor = $encryptor;

        return $this;
    }

    final public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        $this->validate();

        return (null === $value) ? null : $this->encryptor->encrypt((string)$value);
    }

    final public function convertToPHPValue($value, AbstractPlatform $platform): ?string
    {
        $this->validate();

        return (null === $value) ? null : $this->encryptor->decrypt((string)$value);
    }

    private function validate(): void
    {
        if (false === isset($this->encryptor)) {
            throw new Exception('the encryptor was not set');
        }
    }
}
