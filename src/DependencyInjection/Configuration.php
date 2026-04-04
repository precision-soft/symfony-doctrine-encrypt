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
            ->isRequired()
            ->end();
        $nodeBuilder->arrayNode('enabled_types')
            ->scalarPrototype()
            ->defaultNull()
            ->end()
            ->end();
        $nodeBuilder->arrayNode('encryptors')
            ->scalarPrototype()
            ->defaultNull()
            ->end()
            ->end();
        $nodeBuilder->end();

        return $treeBuilder;
    }
}
