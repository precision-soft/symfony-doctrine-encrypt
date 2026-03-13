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
        $loader = new PhpFileLoader($containerBuilder, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.php');

        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.salt', $config['salt']);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.enabled_types', $config['enabled_types']);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.encryptors', $config['encryptors']);
    }
}
