<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PHPUnit\Framework\Assert;

/**
 * @internal
 */
final class Base64Decoder
{
    public static function decodeStrict(string $value): string
    {
        $decoded = \base64_decode($value, true);

        Assert::assertIsString($decoded, 'Expected a strictly valid base64 payload.');

        return $decoded;
    }
}
