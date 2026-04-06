<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test;

use Doctrine\DBAL\Types\Type;
use Mockery;
use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\PrecisionSoftDoctrineEncryptBundle;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;
use PrecisionSoft\Symfony\Phpunit\MockDto;
use PrecisionSoft\Symfony\Phpunit\TestCase\AbstractTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class PrecisionSoftDoctrineEncryptBundleTest extends AbstractTestCase
{
    public static function getMockDto(): MockDto
    {
        return new MockDto(PrecisionSoftDoctrineEncryptBundle::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->removeTypeIfExists('encryptedAes256_bundle_test');
        $this->removeTypeIfExists('encryptedAes256fixed_bundle_test');
    }

    public function testBootRegistersTypesAndSetsEncryptors(): void
    {
        $salt = \str_repeat('s', 32);
        $aes256Encryptor = new Aes256Encryptor($salt);
        $aes256FixedEncryptor = new Aes256FixedEncryptor($salt);

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

        static::assertSame(true, Type::hasType(Aes256Type::getFullName()));
        static::assertSame(true, Type::hasType(Aes256FixedType::getFullName()));

        /** @var Aes256Type $aes256Type */
        $aes256Type = Type::getType(Aes256Type::getFullName());
        static::assertInstanceOf(EncryptorInterface::class, $aes256Type->getEncryptor());

        /** @var Aes256FixedType $aes256FixedType */
        $aes256FixedType = Type::getType(Aes256FixedType::getFullName());
        static::assertInstanceOf(EncryptorInterface::class, $aes256FixedType->getEncryptor());
    }

    public function testBootWithEnabledTypesFiltersRegistration(): void
    {
        $salt = \str_repeat('s', 32);
        $aes256Encryptor = new Aes256Encryptor($salt);
        $aes256FixedEncryptor = new Aes256FixedEncryptor($salt);

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
            ->andReturn([Aes256Type::getFullName()]);

        $precisionSoftDoctrineEncryptBundle = new PrecisionSoftDoctrineEncryptBundle();
        $precisionSoftDoctrineEncryptBundle->setContainer($containerInterface);
        $precisionSoftDoctrineEncryptBundle->boot();

        static::assertSame(true, Type::hasType(Aes256Type::getFullName()));
    }

    public function testBootThrowsTypeNotFoundExceptionForMissingType(): void
    {
        $salt = \str_repeat('s', 32);
        $encryptorFactory = new EncryptorFactory([
            new Aes256Encryptor($salt),
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

        $precisionSoftDoctrineEncryptBundle->boot();

        $this->expectNotToPerformAssertions();
    }

    private function removeTypeIfExists(string $typeName): void
    {
        /** @info Doctrine Type registry does not natively support removal, use override mechanism instead */
        if (Type::hasType($typeName)) {
            Type::overrideType($typeName, Type::getType($typeName)::class);
        }
    }
}
