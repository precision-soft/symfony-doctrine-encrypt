<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example;

use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Example\Service\CustomerDirectory;
use PrecisionSoft\Doctrine\Encrypt\PrecisionSoftDoctrineEncryptBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;

/**
 * The application around the directory: one database, one salts map. An application reads both from its environment; the example takes them as arguments so a test can boot the same directory against another engine, or with the next salt.
 */
class CustomerDirectoryKernel extends Kernel
{
    use MicroKernelTrait;

    /** @param array<string, string> $saltsByVersion */
    public function __construct(
        string $environment,
        protected readonly string $databaseUrl,
        protected readonly array $saltsByVersion,
        protected readonly string $currentSaltVersion,
        protected readonly ?string $legacySaltVersion = null,
    ) {
        parent::__construct($environment, false);
    }

    public function registerBundles(): iterable
    {
        return [new FrameworkBundle(), new DoctrineBundle(), new PrecisionSoftDoctrineEncryptBundle()];
    }

    public function getCacheDir(): string
    {
        return \dirname(__DIR__) . '/var/cache/' . $this->environment;
    }

    public function getLogDir(): string
    {
        return \dirname(__DIR__) . '/var/log';
    }

    protected function configureContainer(ContainerConfigurator $containerConfigurator): void
    {
        $containerConfigurator->extension('framework', ['secret' => 'customer-directory', 'test' => true]);

        $containerConfigurator->extension('doctrine', [
            'dbal' => ['url' => $this->databaseUrl],
            'orm' => [
                'auto_generate_proxy_classes' => true,
                'mappings' => [
                    'CustomerDirectory' => [
                        'type' => 'attribute',
                        'dir' => __DIR__ . '/Entity',
                        'prefix' => 'PrecisionSoft\Doctrine\Encrypt\Example\Entity',
                        'is_bundle' => false,
                    ],
                ],
            ],
        ]);

        $containerConfigurator->extension('precision_soft_doctrine_encrypt', [
            'salts' => $this->saltsByVersion,
            'current_salt_version' => $this->currentSaltVersion,
            'legacy_salt_version' => $this->legacySaltVersion,
            'encryptors' => [Aes256Encryptor::class, Aes256FixedEncryptor::class],
            'enabled_types' => ['encryptedAes256', 'encryptedAes256fixed'],
        ]);

        $containerConfigurator->services()
            ->set(CustomerDirectory::class)
            ->autowire()
            ->public();
    }
}
