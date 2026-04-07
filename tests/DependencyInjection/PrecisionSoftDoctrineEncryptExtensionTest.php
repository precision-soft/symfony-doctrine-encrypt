<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\DependencyInjection;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\DependencyInjection\PrecisionSoftDoctrineEncryptExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * @internal
 */
final class PrecisionSoftDoctrineEncryptExtensionTest extends TestCase
{
    public function testLoadSetsParameters(): void
    {
        $extension = new PrecisionSoftDoctrineEncryptExtension();
        $container = new ContainerBuilder();

        $extension->load(
            [
                [
                    'salt' => 'my-secret-salt-for-testing-1234567890',
                    'enabled_types' => ['encryptedAes256'],
                    'encryptors' => ['App\\Encryptor\\Custom'],
                ],
            ],
            $container,
        );

        static::assertSame(
            'my-secret-salt-for-testing-1234567890',
            $container->getParameter('precision_soft_doctrine_encrypt.salt'),
        );
        static::assertSame(
            ['encryptedAes256'],
            $container->getParameter('precision_soft_doctrine_encrypt.enabled_types'),
        );
        static::assertSame(
            ['App\\Encryptor\\Custom'],
            $container->getParameter('precision_soft_doctrine_encrypt.encryptors'),
        );
    }

    public function testLoadWithMinimalConfigSetsDefaults(): void
    {
        $extension = new PrecisionSoftDoctrineEncryptExtension();
        $container = new ContainerBuilder();

        $extension->load(
            [
                [
                    'salt' => 'minimal-salt-value-long-enough-for-test',
                ],
            ],
            $container,
        );

        static::assertSame(
            'minimal-salt-value-long-enough-for-test',
            $container->getParameter('precision_soft_doctrine_encrypt.salt'),
        );
        static::assertSame(
            [],
            $container->getParameter('precision_soft_doctrine_encrypt.enabled_types'),
        );
        static::assertSame(
            [],
            $container->getParameter('precision_soft_doctrine_encrypt.encryptors'),
        );
    }

    public function testDoctrineEncryptorConstant(): void
    {
        static::assertSame(
            'precision-soft.doctrine.encryptor',
            PrecisionSoftDoctrineEncryptExtension::DOCTRINE_ENCRYPTOR,
        );
    }
}
