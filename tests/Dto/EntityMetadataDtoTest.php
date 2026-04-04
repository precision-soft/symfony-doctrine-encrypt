<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Dto;

use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;

/**
 * @internal
 */
final class EntityMetadataDtoTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testGetClassMetadata(): void
    {
        $classMetadata = Mockery::mock(ClassMetadata::class);
        $fields = ['email' => 'encryptedAes256'];

        $entityMetadataDto = new EntityMetadataDto($classMetadata, $fields);

        static::assertSame($classMetadata, $entityMetadataDto->getClassMetadata());
    }

    public function testGetEncryptionFields(): void
    {
        $classMetadata = Mockery::mock(ClassMetadata::class);
        $fields = ['email' => 'encryptedAes256', 'ssn' => 'encryptedAes256fixed'];

        $entityMetadataDto = new EntityMetadataDto($classMetadata, $fields);

        static::assertSame($fields, $entityMetadataDto->getEncryptionFields());
    }

    public function testEmptyEncryptionFields(): void
    {
        $classMetadata = Mockery::mock(ClassMetadata::class);

        $entityMetadataDto = new EntityMetadataDto($classMetadata, []);

        static::assertSame([], $entityMetadataDto->getEncryptionFields());
    }
}
