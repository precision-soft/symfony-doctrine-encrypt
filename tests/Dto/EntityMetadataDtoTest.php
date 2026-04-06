<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Dto;

use Doctrine\Persistence\Mapping\ClassMetadata;
use Mockery;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;

/**
 * @internal
 */
final class EntityMetadataDtoTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        return new MockDto(EntityMetadataDto::class);
    }

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
