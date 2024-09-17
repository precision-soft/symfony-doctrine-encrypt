<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Dto;

use Doctrine\Persistence\Mapping\ClassMetadata;

class EntityMetadataDto
{
    private ClassMetadata $classMetadata;
    private array $encryptionFields;

    public function __construct(
        ClassMetadata $classMetadata,
        array $encryptionFields,
    ) {
        $this->classMetadata = $classMetadata;
        $this->encryptionFields = $encryptionFields;
    }

    public function getClassMetadata(): ?ClassMetadata
    {
        return $this->classMetadata;
    }

    public function getEncryptionFields(): ?array
    {
        return $this->encryptionFields;
    }
}
