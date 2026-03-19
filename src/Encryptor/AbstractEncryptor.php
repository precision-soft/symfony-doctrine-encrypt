<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Type\AbstractType;

abstract class AbstractEncryptor
{
    public const ENCRYPTION_MARKER = '<ENC>';

    abstract public function getTypeClass(): ?string;

    public function __construct(
        #[\SensitiveParameter]
        protected readonly string $salt,
    ) {}

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
}
