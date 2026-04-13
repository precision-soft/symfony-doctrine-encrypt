<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt;

use Doctrine\DBAL\Types\Type;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class PrecisionSoftDoctrineEncryptBundle extends Bundle
{
    public function boot(): void
    {
        parent::boot();

        if (null === $this->container) {
            return;
        }

        $this->registerTypes();
    }

    protected function registerTypes(): void
    {
        if (null === $this->container) {
            return;
        }

        /** required because of how doctrine instantiates its types */
        /** @var EncryptorFactory $encryptorFactory */
        $encryptorFactory = $this->container->get(EncryptorFactory::class);

        /** @var string[] $enabledTypes */
        $enabledTypes = $this->container->getParameter('precision_soft_doctrine_encrypt.enabled_types');
        $missingTypes = \array_diff($enabledTypes, $encryptorFactory->getTypeNames());

        if ([] !== $missingTypes) {
            throw new TypeNotFoundException(\sprintf('no type found for `%s`', \implode(', ', $missingTypes)));
        }

        foreach ($encryptorFactory->getEncryptors() as $encryptor) {
            $typeClass = $encryptor->getTypeClass();

            if (null === $typeClass) {
                continue;
            }

            $typeName = $encryptor->getTypeName();

            if (null === $typeName) {
                continue;
            }

            if ([] !== $enabledTypes && false === \in_array($typeName, $enabledTypes, true)) {
                continue;
            }

            if (false === Type::hasType($typeName)) {
                Type::addType($typeName, $typeClass);
            }

            /** @var AbstractType $encryptedType */
            $encryptedType = Type::getType($typeName);
            $encryptedType->setEncryptor($encryptor);
        }
    }
}
