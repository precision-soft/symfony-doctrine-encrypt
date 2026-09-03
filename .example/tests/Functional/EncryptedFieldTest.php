<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Functional;

use PHPUnit\Framework\Attributes\DataProviderExternal;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDatabase;
use PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility\CustomerDirectoryTestCase;

/** @internal */
final class EncryptedFieldTest extends CustomerDirectoryTestCase
{
    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testARegisteredUserIsStoredAsCiphertextAndReadBackAsPlaintext(string $environmentVariable): void
    {
        $kernel = $this->bootDirectory($environmentVariable);
        $customerDirectory = $this->getDirectory($kernel);

        $user = $customerDirectory->register('Ada', 'ada@example.com', '+40 700 000 001', '1 Analytical Lane');
        $id = $user->getId();

        static::assertIsInt($id);

        $storedRow = CustomerDatabase::fetchStoredRow($this->getConnection($kernel), $id);

        static::assertSame('Ada', $storedRow['displayName']);
        $this->assertStoredAsCiphertext($storedRow['email'], $this->getCurrentEnvelopePrefix($kernel, 'encryptedAes256fixed'));
        $this->assertStoredAsCiphertext($storedRow['phone'], $this->getCurrentEnvelopePrefix($kernel));
        $this->assertStoredAsCiphertext($storedRow['address'], $this->getCurrentEnvelopePrefix($kernel));

        static::assertTrue($customerDirectory->hasStoredCiphertext($user, 'email'));
        static::assertTrue($customerDirectory->hasStoredCiphertext($user, 'phone'));

        $this->getEntityManager($kernel)->clear();

        $reloaded = $customerDirectory->findById($id);

        static::assertSame('ada@example.com', $reloaded->getEmail());
        static::assertSame('+40 700 000 001', $reloaded->getPhone());
        static::assertSame('1 Analytical Lane', $reloaded->getAddress());
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testADeterministicColumnRepeatsItsCiphertextAndARandomColumnNeverDoes(string $environmentVariable): void
    {
        $kernel = $this->bootDirectory($environmentVariable);
        $customerDirectory = $this->getDirectory($kernel);
        $connection = $this->getConnection($kernel);

        $first = $customerDirectory->register('Ada', 'shared@example.com', '+40 700 000 002');
        $second = $customerDirectory->register('Grace', 'shared@example.com', '+40 700 000 002');

        static::assertIsInt($first->getId());
        static::assertIsInt($second->getId());

        $firstRow = CustomerDatabase::fetchStoredRow($connection, $first->getId());
        $secondRow = CustomerDatabase::fetchStoredRow($connection, $second->getId());

        static::assertSame($firstRow['email'], $secondRow['email'], 'the deterministic e-mail is what makes the lookup possible');
        static::assertNotSame($firstRow['phone'], $secondRow['phone'], 'the random phone hides that two users share a number');
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testANullValueStaysNullOnDisk(string $environmentVariable): void
    {
        $kernel = $this->bootDirectory($environmentVariable);
        $customerDirectory = $this->getDirectory($kernel);

        $user = $customerDirectory->register('Ada', 'ada@example.com', '+40 700 000 003');

        static::assertIsInt($user->getId());
        static::assertNull(CustomerDatabase::fetchStoredRow($this->getConnection($kernel), $user->getId())['address']);
        static::assertFalse($customerDirectory->hasStoredCiphertext($user, 'address'));
    }

    #[DataProviderExternal(CustomerDatabase::class, 'dataProviderEngine')]
    public function testTheMappingTellsWhichFieldsAreEncrypted(string $environmentVariable): void
    {
        $customerDirectory = $this->getDirectory($this->bootDirectory($environmentVariable));

        static::assertSame(
            ['email' => 'encryptedAes256fixed', 'phone' => 'encryptedAes256', 'address' => 'encryptedAes256'],
            $customerDirectory->getEncryptedFields(),
        );
        static::assertTrue($customerDirectory->hasEncryption('email'));
        static::assertFalse($customerDirectory->hasEncryption('displayName'));
    }
}
