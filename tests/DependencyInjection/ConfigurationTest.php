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
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'my-very-long-secret-salt-value-here',
                ],
            ],
        );

        static::assertSame('my-very-long-secret-salt-value-here', $processedConfiguration['salt']);
        static::assertSame([], $processedConfiguration['enabled_types']);
        static::assertSame([], $processedConfiguration['encryptors']);
    }

    public function testFullConfiguration(): void
    {
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'my-secret-salt-for-full-config-test',
                    'enabled_types' => ['encryptedAes256', 'encryptedAes256fixed'],
                    'encryptors' => ['App\\Encryptor\\CustomEncryptor'],
                ],
            ],
        );

        static::assertSame('my-secret-salt-for-full-config-test', $processedConfiguration['salt']);
        static::assertSame(['encryptedAes256', 'encryptedAes256fixed'], $processedConfiguration['enabled_types']);
        static::assertSame(['App\\Encryptor\\CustomEncryptor'], $processedConfiguration['encryptors']);
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
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'some-salt-value-long-enough-for-test',
                ],
            ],
        );

        static::assertSame([], $processedConfiguration['enabled_types']);
    }

    public function testEmptyEncryptorsDefaultsToEmptyArray(): void
    {
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'some-salt-value-long-enough-for-test',
                ],
            ],
        );

        static::assertSame([], $processedConfiguration['encryptors']);
    }

    public function testTreeBuilderHasCorrectRootName(): void
    {
        $treeBuilder = $this->configuration->getConfigTreeBuilder();
        $tree = $treeBuilder->buildTree();

        static::assertSame('precision_soft_doctrine_encrypt', $tree->getName());
    }

    public function testMultipleConfigsAreMerged(): void
    {
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => 'first-salt-long-enough-for-validation',
                    'enabled_types' => ['type1'],
                ],
                [
                    'salt' => 'second-salt-long-enough-for-valid',
                    'enabled_types' => ['type2'],
                ],
            ],
        );

        static::assertSame('second-salt-long-enough-for-valid', $processedConfiguration['salt']);
        static::assertSame(['type1', 'type2'], $processedConfiguration['enabled_types']);
    }

    public function testSaltsMapWithCurrentSaltVersion(): void
    {
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => [
                        'v1' => \str_repeat('a', 32),
                        'v2' => \str_repeat('b', 32),
                    ],
                    'current_salt_version' => 'v2',
                ],
            ],
        );

        static::assertNull($processedConfiguration['salt']);
        static::assertSame(
            ['v1' => \str_repeat('a', 32), 'v2' => \str_repeat('b', 32)],
            $processedConfiguration['salts'],
        );
        static::assertSame('v2', $processedConfiguration['current_salt_version']);
    }

    public function testSaltAndSaltsAreMutuallyExclusive(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('mutually exclusive');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => \str_repeat('a', 32),
                    'salts' => ['v1' => \str_repeat('b', 32)],
                    'current_salt_version' => 'v1',
                ],
            ],
        );
    }

    public function testSaltsRequiresCurrentSaltVersion(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('current_salt_version');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['v1' => \str_repeat('a', 32)],
                ],
            ],
        );
    }

    public function testCurrentSaltVersionMustReferenceKeyInSalts(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('must reference a key');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['v1' => \str_repeat('a', 32)],
                    'current_salt_version' => 'does-not-exist',
                ],
            ],
        );
    }

    /** @info SDE-154 — salt-version keys with null bytes would break the wire-format framing; configuration must reject them */
    public function testSaltVersionKeyWithNullByteRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('salt-version identifiers must match');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ["v1\0bad" => \str_repeat('a', 32)],
                    'current_salt_version' => "v1\0bad",
                ],
            ],
        );
    }

    /** @info SDE-154 — salt-version keys with whitespace must be rejected */
    public function testSaltVersionKeyWithSpaceRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('salt-version identifiers must match');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['v 1' => \str_repeat('a', 32)],
                    'current_salt_version' => 'v 1',
                ],
            ],
        );
    }

    /** @info SDE-154 — salt-version keys with non-ASCII runes must be rejected */
    public function testSaltVersionKeyWithNonAsciiRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('salt-version identifiers must match');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['vé' => \str_repeat('a', 32)],
                    'current_salt_version' => 'vé',
                ],
            ],
        );
    }

    /** @info SDE-152 — `legacy_salt_version` parses cleanly and must reference a key in the salts map */
    public function testLegacySaltVersionMustReferenceKeyInSalts(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('`legacy_salt_version` must reference a key');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['v1' => \str_repeat('a', 32), 'v2' => \str_repeat('b', 32)],
                    'current_salt_version' => 'v2',
                    'legacy_salt_version' => 'missing',
                ],
            ],
        );
    }

    /** @info SDE-152 — the happy path where `legacy_salt_version` is accepted and stored */
    public function testLegacySaltVersionParsedFromConfiguration(): void
    {
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['v1' => \str_repeat('a', 32), 'v2' => \str_repeat('b', 32)],
                    'current_salt_version' => 'v2',
                    'legacy_salt_version' => 'v1',
                ],
            ],
        );

        static::assertSame('v1', $processedConfiguration['legacy_salt_version']);
    }

    /** @info SDE-152 — `legacy_salt_version` has no meaning under the single-salt `salt` shorthand and must be rejected there */
    public function testLegacySaltVersionRejectedWithSingleSaltShorthand(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('`legacy_salt_version` requires `salts`');

        $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salt' => \str_repeat('a', 32),
                    'legacy_salt_version' => 'v1',
                ],
            ],
        );
    }

    /** @info SDE-154 — salt-version identifiers containing a dot (e.g. `v1.0`, `2026.04`) are accepted */
    public function testSaltVersionKeyWithDotAccepted(): void
    {
        $processedConfiguration = $this->processor->processConfiguration(
            $this->configuration,
            [
                [
                    'salts' => ['v1.0' => \str_repeat('a', 32), '2026.04' => \str_repeat('b', 32)],
                    'current_salt_version' => '2026.04',
                    'legacy_salt_version' => 'v1.0',
                ],
            ],
        );

        static::assertSame('2026.04', $processedConfiguration['current_salt_version']);
        static::assertSame('v1.0', $processedConfiguration['legacy_salt_version']);
    }
}
