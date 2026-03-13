<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Service;

use Doctrine\DBAL\Types\Type;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Exception\DuplicateEncryptorException;
use PrecisionSoft\Doctrine\Encrypt\Exception\EncryptorNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;

class EncryptorFactory
{
    /** @var array<class-string, EncryptorInterface> */
    private array $encryptors;

    /** @var string[] */
    private array $typeNames;

    public function __construct(iterable $encryptors)
    {
        /** @todo register only the configured encryptors */
        $this->encryptors = [];
        $this->typeNames = [];

        /** @var EncryptorInterface $encryptor */
        foreach ($encryptors as $encryptor) {
            $typeName = $encryptor->getTypeName();

            if (true === \in_array($typeName, $this->typeNames, true)) {
                throw new DuplicateEncryptorException(
                    \sprintf('multiple encryptors defined for type `%s`', $typeName),
                );
            }

            $this->typeNames[] = $typeName;
            $this->encryptors[$encryptor::class] = $encryptor;
        }
    }

    /**
     * @return array<class-string, EncryptorInterface>
     *
     * @internal
     */
    public function getEncryptors(): array
    {
        return $this->encryptors;
    }

    /**
     * @return string[]
     *
     * @internal
     */
    public function getTypeNames(): array
    {
        return $this->typeNames;
    }

    public function getEncryptor(string $encryptorClass): EncryptorInterface
    {
        if (false === isset($this->encryptors[$encryptorClass])) {
            throw new EncryptorNotFoundException(\sprintf('no encryptor found for `%s`', $encryptorClass));
        }

        return $this->encryptors[$encryptorClass];
    }

    public function getEncryptorByType(string $typeName): EncryptorInterface
    {
        foreach ($this->encryptors as $encryptor) {
            if ($encryptor->getTypeName() === $typeName) {
                return $encryptor;
            }
        }

        throw new EncryptorNotFoundException(\sprintf('no encryptor found for type `%s`', $typeName));
    }

    public function getType(string $typeName): AbstractType
    {
        if (false === \in_array($typeName, $this->typeNames, true)) {
            throw new TypeNotFoundException(\sprintf('no type found for `%s`', $typeName));
        }

        $type = Type::getType($typeName);

        if (false === ($type instanceof AbstractType)) {
            throw new Exception(
                \sprintf('the encrypted type must extend `%s`', AbstractType::class),
            );
        }

        return $type;
    }
}
