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
        $fields = ['email' => 'encryptedAES256'];

        $dto = new EntityMetadataDto($classMetadata, $fields);

        static::assertSame($classMetadata, $dto->getClassMetadata());
    }

    public function testGetEncryptionFields(): void
    {
        $classMetadata = Mockery::mock(ClassMetadata::class);
        $fields = ['email' => 'encryptedAES256', 'ssn' => 'encryptedAES256fixed'];

        $dto = new EntityMetadataDto($classMetadata, $fields);

        static::assertSame($fields, $dto->getEncryptionFields());
    }

    public function testEmptyEncryptionFields(): void
    {
        $classMetadata = Mockery::mock(ClassMetadata::class);

        $dto = new EntityMetadataDto($classMetadata, []);

        static::assertSame([], $dto->getEncryptionFields());
    }
}
