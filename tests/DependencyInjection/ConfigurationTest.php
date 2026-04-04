<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\DependencyInjection;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\DependencyInjection\Configuration;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * @internal
 */
final class ConfigurationTest extends TestCase
{
    private Processor $processor;
    private Configuration $configuration;

    protected function setUp(): void
    {
        $this->processor = new Processor();
        $this->configuration = new Configuration();
    }

    public function testMinimalValidConfiguration(): void
    {
        $config = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'my-very-long-secret-salt-value-here',
                ],
            ],
        );

        static::assertSame('my-very-long-secret-salt-value-here', $config['salt']);
        static::assertSame([], $config['enabled_types']);
        static::assertSame([], $config['encryptors']);
    }

    public function testFullConfiguration(): void
    {
        $config = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'my-secret-salt',
                    'enabled_types' => ['encryptedAES256', 'encryptedAES256fixed'],
                    'encryptors' => ['App\\Encryptor\\CustomEncryptor'],
                ],
            ],
        );

        static::assertSame('my-secret-salt', $config['salt']);
        static::assertSame(['encryptedAES256', 'encryptedAES256fixed'], $config['enabled_types']);
        static::assertSame(['App\\Encryptor\\CustomEncryptor'], $config['encryptors']);
    }

    public function testSaltIsRequired(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [],
            ],
        );
    }

    public function testEmptyEnabledTypesDefaultsToEmptyArray(): void
    {
        $config = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'some-salt-value',
                ],
            ],
        );

        static::assertSame(true, \is_array($config['enabled_types']));
        static::assertSame([], $config['enabled_types']);
    }

    public function testEmptyEncryptorsDefaultsToEmptyArray(): void
    {
        $config = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'some-salt-value',
                ],
            ],
        );

        static::assertSame(true, \is_array($config['encryptors']));
        static::assertSame([], $config['encryptors']);
    }

    public function testTreeBuilderHasCorrectRootName(): void
    {
        $treeBuilder = $this->configuration->getConfigTreeBuilder();
        $tree = $treeBuilder->buildTree();

        static::assertSame('precision_soft_doctrine_encrypt', $tree->getName());
    }

    public function testMultipleConfigsAreMerged(): void
    {
        $config = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'first-salt',
                    'enabled_types' => ['type1'],
                ],
                [
                    'salt' => 'second-salt',
                    'enabled_types' => ['type2'],
                ],
            ],
        );

        // The last value wins for scalar nodes.
        static::assertSame('second-salt', $config['salt']);
        // Array nodes are merged.
        static::assertSame(['type1', 'type2'], $config['enabled_types']);
    }
}
