<?php

/*
 * Copyright (c) Precision Soft
 */

$header = 'Copyright (c) Precision Soft';

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
    ->exclude(['var', 'node_modules', 'vendor', 'Test/Fixture']);

if (true === \is_dir(__DIR__ . '/.dev/phpstan')) {
    $finder->in(__DIR__ . '/.dev/phpstan');
}

if (true === \is_dir(__DIR__ . '/.example')) {
    $finder->in(__DIR__ . '/.example');
}

return (new PhpCsFixer\Config())->setRules(
    [
        '@PER-CS2.0' => true,
        '@PER-CS2.0:risky' => true,
        'header_comment' => ['header' => $header],
        'cast_spaces' => ['space' => 'none'],
        'type_declaration_spaces' => true,
    ],
)
    ->setRiskyAllowed(true)
    ->setUsingCache(true)
    ->setFinder($finder);
