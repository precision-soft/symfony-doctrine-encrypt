<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Service;

use Doctrine\DBAL\Types\Type;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\DuplicateEncryptorException;
use PrecisionSoft\Doctrine\Encrypt\Exception\EncryptorNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;

class EncryptorFactory
{
    /** @var array<class-string, EncryptorInterface> */
    private array $encryptors;

    /** @var array<string, EncryptorInterface> */
    private array $encryptorsByTypeName;

    /** @var string[] */
    private array $typeNames;

    /**
     * @param iterable<EncryptorInterface> $encryptors
     * @param class-string[] $enabledEncryptors
     */
    public function __construct(
        iterable $encryptors,
        array $enabledEncryptors = [],
    ) {
        $this->encryptors = [];
        $this->encryptorsByTypeName = [];
        $this->typeNames = [];

        foreach ($encryptors as $encryptor) {
            /** @info FakeEncryptor is always registered regardless of enabledEncryptors — it is required by the database migration commands */
            if ([] !== $enabledEncryptors && false === ($encryptor instanceof FakeEncryptor) && false === \in_array($encryptor::class, $enabledEncryptors, true)) {
                continue;
            }

            $typeName = $encryptor->getTypeName();

            if (null !== $typeName) {
                if (true === \in_array($typeName, $this->typeNames, true)) {
                    throw new DuplicateEncryptorException(
                        \sprintf('multiple encryptors defined for type `%s`', $typeName),
                    );
                }

                $this->typeNames[] = $typeName;
                $this->encryptorsByTypeName[$typeName] = $encryptor;
            }

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

    /**
     * @param class-string $encryptorClass
     */
    public function getEncryptor(string $encryptorClass): EncryptorInterface
    {
        if (false === isset($this->encryptors[$encryptorClass])) {
            throw new EncryptorNotFoundException(\sprintf('no encryptor found for `%s`', $encryptorClass));
        }

        return $this->encryptors[$encryptorClass];
    }

    public function getEncryptorByType(string $typeName): EncryptorInterface
    {
        if (false === isset($this->encryptorsByTypeName[$typeName])) {
            throw new EncryptorNotFoundException(\sprintf('no encryptor found for type `%s`', $typeName));
        }

        return $this->encryptorsByTypeName[$typeName];
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
