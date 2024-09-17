<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

use PrecisionSoft\Doctrine\Encrypt\Command\AbstractDatabaseCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseDecryptCommand;
use PrecisionSoft\Doctrine\Encrypt\Command\DatabaseEncryptCommand;
use PrecisionSoft\Doctrine\Encrypt\DependencyInjection\PrecisionSoftDoctrineEncryptExtension;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AbstractEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;

return function (ContainerConfigurator $containerConfigurator) {
    $services = $containerConfigurator->services();

    $services->set(AbstractEncryptor::class)
        ->abstract()
        ->arg('$salt', '%precision_soft_doctrine_encrypt.salt%');

    $services->set(AES256Encryptor::class)
        ->parent(AbstractEncryptor::class)
        ->tag(PrecisionSoftDoctrineEncryptExtension::DOCTRINE_ENCRYPTOR);

    $services->set(FakeEncryptor::class)
        ->tag(PrecisionSoftDoctrineEncryptExtension::DOCTRINE_ENCRYPTOR);

    $services->set(AES256FixedEncryptor::class)
        ->parent(AbstractEncryptor::class)
        ->tag(PrecisionSoftDoctrineEncryptExtension::DOCTRINE_ENCRYPTOR);

    $services->set(EncryptorFactory::class)
        ->public()
        ->arg('$encryptors', new TaggedIteratorArgument(PrecisionSoftDoctrineEncryptExtension::DOCTRINE_ENCRYPTOR));

    $services->set(AbstractDatabaseCommand::class)
        ->abstract()
        ->arg('$managerRegistry', new Reference('doctrine'))
        ->arg('$encryptorFactory', new Reference(EncryptorFactory::class))
        ->arg('$entityService', new Reference(EntityService::class));

    $services->set(DatabaseEncryptCommand::class)
        ->parent(AbstractDatabaseCommand::class)
        ->tag('console.command');

    $services->set(DatabaseDecryptCommand::class)
        ->parent(AbstractDatabaseCommand::class)
        ->tag('console.command');

    $services->set(EntityService::class)
        ->arg('$managerRegistry', new Reference('doctrine'))
        ->arg('$encryptorFactory', new Reference(EncryptorFactory::class));
};
