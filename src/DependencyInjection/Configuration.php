<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('precision_soft_doctrine_encrypt');
        $rootNode = $treeBuilder->getRootNode();

        $nodeBuilder = $rootNode->children();

        $nodeBuilder->scalarNode('salt')
            ->defaultNull();

        $nodeBuilder->arrayNode('salts')
            ->useAttributeAsKey('version')
            ->scalarPrototype();

        $nodeBuilder->scalarNode('current_salt_version')
            ->defaultNull();

        $nodeBuilder->arrayNode('enabled_types')
            ->scalarPrototype()
            ->defaultNull();

        $nodeBuilder->arrayNode('encryptors')
            ->scalarPrototype()
            ->defaultNull();

        $rootNode
            ->validate()
            ->ifTrue(static fn(array $value): bool => null === $value['salt'] && [] === $value['salts'])
            ->thenInvalid('one of `salt` or `salts` must be provided')
            ->end()
            ->validate()
            ->ifTrue(static fn(array $value): bool => null !== $value['salt'] && [] !== $value['salts'])
            ->thenInvalid('`salt` and `salts` are mutually exclusive — use one or the other')
            ->end()
            ->validate()
            ->ifTrue(static fn(array $value): bool => [] !== $value['salts'] && null === $value['current_salt_version'])
            ->thenInvalid('`current_salt_version` is required when `salts` is used')
            ->end()
            ->validate()
            ->ifTrue(static fn(array $value): bool => [] !== $value['salts'] && null !== $value['current_salt_version'] && false === \array_key_exists($value['current_salt_version'], $value['salts']))
            ->thenInvalid('`current_salt_version` must reference a key in `salts`')
            ->end();

        return $treeBuilder;
    }
}
