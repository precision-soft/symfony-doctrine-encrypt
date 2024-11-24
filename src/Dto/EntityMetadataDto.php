<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Dto;

use Doctrine\Persistence\Mapping\ClassMetadata;

class EntityMetadataDto
{
    public function __construct(
        private readonly ClassMetadata $classMetadata,
        private readonly array $encryptionFields,
    ) {}

    public function getClassMetadata(): ?ClassMetadata
    {
        return $this->classMetadata;
    }

    public function getEncryptionFields(): ?array
    {
        return $this->encryptionFields;
    }
}
