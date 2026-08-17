<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Exception;

use Exception as BaseException;
use PHPUnit\Framework\TestCase;
use PrecisionSoft\Doctrine\Encrypt\Contract\ExceptionInterface;
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

    public function testExceptionImplementsExceptionInterface(): void
    {
        static::assertInstanceOf(ExceptionInterface::class, new Exception('test'));
        static::assertInstanceOf(ExceptionInterface::class, new StopException('stop'));
    }

    public function testContextDefaultsToAnEmptyArray(): void
    {
        static::assertSame([], (new Exception('test'))->getContext());
        static::assertSame([], (new Exception('test', 0, null, null))->getContext());
    }

    public function testContextIsReadBackFromTheConstructor(): void
    {
        $exception = new TypeNotFoundException('type not found', 0, null, ['typeName' => 'encrypted_string']);

        static::assertSame(['typeName' => 'encrypted_string'], $exception->getContext());
    }

    public function testSetContextReplacesTheContextAndIsFluent(): void
    {
        $exception = new Exception('test', 0, null, ['first' => 1]);

        static::assertSame($exception, $exception->setContext(['second' => 2]));
        static::assertSame(['second' => 2], $exception->getContext());

        $exception->setContext(null);

        static::assertSame([], $exception->getContext());
    }

    public function testTheContextDoesNotLeakIntoTheMessageCodeOrPrevious(): void
    {
        $previous = new BaseException('root cause');

        $exception = new Exception('test', 7, $previous, ['key' => 'value']);

        static::assertSame('test', $exception->getMessage());
        static::assertSame(7, $exception->getCode());
        static::assertSame($previous, $exception->getPrevious());
    }

    public function testTheConstructorDefaultsToAnEmptyMessageZeroCodeAndNoPrevious(): void
    {
        $exception = new Exception();

        static::assertSame('', $exception->getMessage());
        static::assertSame(0, $exception->getCode());
        static::assertNull($exception->getPrevious());
        static::assertSame([], $exception->getContext());
    }
}
