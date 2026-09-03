<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Functional;

use PHPUnit\Framework\Attributes\DataProviderExternal;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDatabase;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDirectoryTestCase;
use PrecisionSoft\Doctrine\Encrypt\Exception\NonDeterministicEncryptorException;

/** @internal */
final class CustomerLookupTest extends CustomerDirectoryTestCase
{
    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testAUserIsFoundByTheDeterministicEmail(string $environmentVariable): void
    {
        $customerDirectory = $this->getDirectory($this->bootDirectory($environmentVariable));

        $customerDirectory->register('Ada', 'ada@example.com', '+40 700 000 001');
        $customerDirectory->register('Grace', 'grace@example.com', '+40 700 000 002');

        $found = $customerDirectory->findByEmail('grace@example.com');

        static::assertNotNull($found);
        static::assertSame('Grace', $found->getDisplayName());
        static::assertNull($customerDirectory->findByEmail('nobody@example.com'));
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testARandomColumnCannotBeSearched(string $environmentVariable): void
    {
        $customerDirectory = $this->getDirectory($this->bootDirectory($environmentVariable));

        $customerDirectory->register('Ada', 'ada@example.com', '+40 700 000 001');

        $this->expectException(NonDeterministicEncryptorException::class);

        $customerDirectory->findByPhone('+40 700 000 001');
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testALookupDuringARotationMatchesEveryActiveSaltVersion(string $environmentVariable): void
    {
        $firstGeneration = $this->getDirectory($this->bootDirectory($environmentVariable));
        $firstGeneration->register('Ada', 'ada@example.com', '+40 700 000 001');

        /* the salt flipped, the rows did not rotate yet: the plain comparison misses, the list of candidates does not */
        $secondGeneration = $this->getDirectory($this->bootDirectory($environmentVariable, self::GENERATION_SECOND));

        static::assertNull($secondGeneration->findByEmail('ada@example.com'));

        $candidates = $secondGeneration->findByEmailAcrossSaltVersions('ada@example.com', $found);

        static::assertCount(2, $candidates);
        static::assertNotNull($found);
        static::assertSame('Ada', $found->getDisplayName());
    }
}
