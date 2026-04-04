<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class PrecisionSoftDoctrineEncryptExtension extends Extension
{
    public const DOCTRINE_ENCRYPTOR = 'precision-soft.doctrine.encryptor';

    public function load(array $configs, ContainerBuilder $containerBuilder): void
    {
        $phpFileLoader = new PhpFileLoader($containerBuilder, new FileLocator(__DIR__ . '/../Resources/config'));
        $phpFileLoader->load('services.php');

        $configuration = new Configuration();
        $processedConfig = $this->processConfiguration($configuration, $configs);

        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.salt', $processedConfig['salt']);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.enabled_types', $processedConfig['enabled_types']);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.encryptors', $processedConfig['encryptors']);
    }
}
