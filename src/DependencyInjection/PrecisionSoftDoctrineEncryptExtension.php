<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\DependencyInjection;

use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
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
        $processedConfiguration = $this->processConfiguration($configuration, $configs);

        if (null !== $processedConfiguration['salt']) {
            $saltsByVersion = [AbstractEncryptor::DEFAULT_SALT_VERSION => $processedConfiguration['salt']];
            $currentSaltVersion = AbstractEncryptor::DEFAULT_SALT_VERSION;
            $legacySaltVersion = AbstractEncryptor::DEFAULT_SALT_VERSION;
        } else {
            $saltsByVersion = $processedConfiguration['salts'];
            $currentSaltVersion = $processedConfiguration['current_salt_version'];
            $legacySaltVersion = $processedConfiguration['legacy_salt_version']
                ?? \array_key_first($saltsByVersion);
        }

        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.salts_by_version', $saltsByVersion);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.current_salt_version', $currentSaltVersion);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.legacy_salt_version', $legacySaltVersion);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.enabled_types', $processedConfiguration['enabled_types']);
        $containerBuilder->setParameter('precision_soft_doctrine_encrypt.encryptors', $processedConfiguration['encryptors']);
    }
}
