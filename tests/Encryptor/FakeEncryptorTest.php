<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Encryptor;

use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\FakeEncryptor;

/**
 * @internal
 */
final class FakeEncryptorTest extends TestCase
{
    private FakeEncryptor $encryptor;

    protected function setUp(): void
    {
        $this->encryptor = new FakeEncryptor();
    }

    public function testEncryptReturnsInputUnchanged(): void
    {
        $value = 'any-value';

        static::assertSame($value, $this->encryptor->encrypt($value));
    }

    public function testDecryptReturnsInputUnchanged(): void
    {
        $value = 'any-value';

        static::assertSame($value, $this->encryptor->decrypt($value));
    }

    public function testGetTypeClassReturnsNull(): void
    {
        static::assertNull($this->encryptor->getTypeClass());
    }

    public function testGetTypeNameReturnsNull(): void
    {
        static::assertNull($this->encryptor->getTypeName());
    }
}
