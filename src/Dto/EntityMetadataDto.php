<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Dto;

use Doctrine\Persistence\Mapping\ClassMetadata;

readonly class EntityMetadataDto
{
    /**
     * @param array<string, string> $encryptionFields
     */
    public function __construct(
        private ClassMetadata $classMetadata,
        private array $encryptionFields,
    ) {}

    public function getClassMetadata(): ClassMetadata
    {
        return $this->classMetadata;
    }

    /**
     * @return array<string, string>
     */
    public function getEncryptionFields(): array
    {
        return $this->encryptionFields;
    }
}
