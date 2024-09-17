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

        $treeBuilder->getRootNode()
            ->children()
            ->scalarNode('salt')->isRequired()->end()
            /* all types are enabled by default */
            ->arrayNode('enabled_types')->scalarPrototype()->defaultNull()->end();

        return $treeBuilder;
    }
}
