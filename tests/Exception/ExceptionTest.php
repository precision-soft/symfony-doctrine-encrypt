<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Exception;

use Exception as BaseException;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Exception\DuplicateEncryptorException;
use PrecisionSoft\Doctrine\Encrypt\Exception\EncryptorNotFoundException;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Exception\FieldNotEncryptedException;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use PrecisionSoft\Doctrine\Encrypt\Exception\TypeNotFoundException;

/**
 * @internal
 */
final class ExceptionTest extends TestCase
{
    public function testExceptionExtendsBaseException(): void
    {
        $exception = new Exception('test');

        static::assertInstanceOf(BaseException::class, $exception);
        static::assertSame('test', $exception->getMessage());
    }

    public function testDuplicateEncryptorExceptionExtendsException(): void
    {
        $exception = new DuplicateEncryptorException('duplicate');

        static::assertInstanceOf(Exception::class, $exception);
        static::assertSame('duplicate', $exception->getMessage());
    }

    public function testEncryptorNotFoundExceptionExtendsException(): void
    {
        $exception = new EncryptorNotFoundException('not found');

        static::assertInstanceOf(Exception::class, $exception);
        static::assertSame('not found', $exception->getMessage());
    }

    public function testFieldNotEncryptedExceptionExtendsException(): void
    {
        $exception = new FieldNotEncryptedException('not encrypted');

        static::assertInstanceOf(Exception::class, $exception);
        static::assertSame('not encrypted', $exception->getMessage());
    }

    public function testStopExceptionExtendsException(): void
    {
        $exception = new StopException('stop');

        static::assertInstanceOf(Exception::class, $exception);
        static::assertSame('stop', $exception->getMessage());
    }

    public function testTypeNotFoundExceptionExtendsException(): void
    {
        $exception = new TypeNotFoundException('type not found');

        static::assertInstanceOf(Exception::class, $exception);
        static::assertSame('type not found', $exception->getMessage());
    }
}
