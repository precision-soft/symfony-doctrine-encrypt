<?php

$header = 'Copyright (c) Precision Soft';

$finder = (new PhpCsFixer\Finder())->in(__DIR__)
    ->exclude(['var', 'vendor']);

return (new PhpCsFixer\Config())->setRules(
    [
        '@PER-CS2.0' => true,
        '@PER-CS2.0:risky' => true,
        'header_comment' => ['header' => $header],
        'cast_spaces' => ['space' => 'none'],
    ]
)
    ->setRiskyAllowed(true)
    ->setUsingCache(true)
    ->setFinder($finder);
