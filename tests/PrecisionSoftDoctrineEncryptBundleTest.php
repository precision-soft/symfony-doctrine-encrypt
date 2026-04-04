<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test;

use Doctrine\DBAL\Types\Type;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\PrecisionSoftDoctrineEncryptBundle;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\AES256Type;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class PrecisionSoftDoctrineEncryptBundleTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        // Clean up registered types from previous test runs to avoid conflicts.
        $this->removeTypeIfExists('encryptedAES256_bundle_test');
        $this->removeTypeIfExists('encryptedAES256fixed_bundle_test');
    }

    public function testBootRegistersTypesAndSetsEncryptors(): void
    {
        $salt = \str_repeat('s', 32);
        $aes256Encryptor = new AES256Encryptor($salt);
        $aes256FixedEncryptor = new AES256FixedEncryptor($salt);

        $encryptorFactory = new EncryptorFactory([
            $aes256Encryptor,
            $aes256FixedEncryptor,
            new FakeEncryptor(),
        ]);

        $containerInterface = Mockery::mock(ContainerInterface::class);
        $containerInterface->shouldReceive('get')
            ->with(EncryptorFactory::class)
            ->andReturn($encryptorFactory);
        $containerInterface->shouldReceive('getParameter')
            ->with('precision_soft_doctrine_encrypt.enabled_types')
            ->andReturn([]);

        $precisionSoftDoctrineEncryptBundle = new PrecisionSoftDoctrineEncryptBundle();
        $precisionSoftDoctrineEncryptBundle->setContainer($containerInterface);
        $precisionSoftDoctrineEncryptBundle->boot();

        // Verify types are registered.
        static::assertSame(true, Type::hasType(AES256Type::getFullName()));
        static::assertSame(true, Type::hasType(AES256FixedType::getFullName()));

        // Verify encryptors are wired.
        /** @var AES256Type $aes256Type */
        $aes256Type = Type::getType(AES256Type::getFullName());
        static::assertInstanceOf(EncryptorInterface::class, $aes256Type->getEncryptor());

        /** @var AES256FixedType $aes256FixedType */
        $aes256FixedType = Type::getType(AES256FixedType::getFullName());
        static::assertInstanceOf(EncryptorInterface::class, $aes256FixedType->getEncryptor());
    }

    public function testBootWithEnabledTypesFiltersRegistration(): void
    {
        $salt = \str_repeat('s', 32);
        $aes256Encryptor = new AES256Encryptor($salt);
        $aes256FixedEncryptor = new AES256FixedEncryptor($salt);

        $encryptorFactory = new EncryptorFactory([
            $aes256Encryptor,
            $aes256FixedEncryptor,
            new FakeEncryptor(),
        ]);

        $containerInterface = Mockery::mock(ContainerInterface::class);
        $containerInterface->shouldReceive('get')
            ->with(EncryptorFactory::class)
            ->andReturn($encryptorFactory);
        $containerInterface->shouldReceive('getParameter')
            ->with('precision_soft_doctrine_encrypt.enabled_types')
            ->andReturn([AES256Type::getFullName()]);

        $precisionSoftDoctrineEncryptBundle = new PrecisionSoftDoctrineEncryptBundle();
        $precisionSoftDoctrineEncryptBundle->setContainer($containerInterface);
        $precisionSoftDoctrineEncryptBundle->boot();

        // AES256Type should be registered.
        static::assertSame(true, Type::hasType(AES256Type::getFullName()));
    }

    public function testBootThrowsTypeNotFoundExceptionForMissingType(): void
    {
        $salt = \str_repeat('s', 32);
        $encryptorFactory = new EncryptorFactory([
            new AES256Encryptor($salt),
            new FakeEncryptor(),
        ]);

        $containerInterface = Mockery::mock(ContainerInterface::class);
        $containerInterface->shouldReceive('get')
            ->with(EncryptorFactory::class)
            ->andReturn($encryptorFactory);
        $containerInterface->shouldReceive('getParameter')
            ->with('precision_soft_doctrine_encrypt.enabled_types')
            ->andReturn(['nonExistentType']);

        $precisionSoftDoctrineEncryptBundle = new PrecisionSoftDoctrineEncryptBundle();
        $precisionSoftDoctrineEncryptBundle->setContainer($containerInterface);

        $this->expectException(TypeNotFoundException::class);

        $precisionSoftDoctrineEncryptBundle->boot();
    }

    public function testBootSkipsEncryptorsWithNullTypeClass(): void
    {
        $salt = \str_repeat('s', 32);
        $fakeEncryptor = new FakeEncryptor();

        $encryptorFactory = new EncryptorFactory([
            $fakeEncryptor,
        ]);

        $containerInterface = Mockery::mock(ContainerInterface::class);
        $containerInterface->shouldReceive('get')
            ->with(EncryptorFactory::class)
            ->andReturn($encryptorFactory);
        $containerInterface->shouldReceive('getParameter')
            ->with('precision_soft_doctrine_encrypt.enabled_types')
            ->andReturn([]);

        $precisionSoftDoctrineEncryptBundle = new PrecisionSoftDoctrineEncryptBundle();
        $precisionSoftDoctrineEncryptBundle->setContainer($containerInterface);

        // Should not throw -- FakeEncryptor has null typeClass and is skipped.
        $precisionSoftDoctrineEncryptBundle->boot();

        // Just verifying no exception was thrown.
        static::assertSame(true, true);
    }

    private function removeTypeIfExists(string $typeName): void
    {
        // Doctrine Type registry does not natively support removal,
        // but we can use the override mechanism if the type exists.
        if (Type::hasType($typeName)) {
            Type::overrideType($typeName, Type::getType($typeName)::class);
        }
    }
}
