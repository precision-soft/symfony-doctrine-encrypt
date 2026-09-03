<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Exception\Exception;

/**
 * A real encryptor whose `encrypt()` gives up after a set number of calls, the shape of a run that dies in the middle of a batch.
 *
 * @internal
 */
final class FailingEncryptor extends Aes256Encryptor
{
    private int $remainingEncryptions = \PHP_INT_MAX;

    public function failAfter(int $successfulEncryptions): static
    {
        $this->remainingEncryptions = $successfulEncryptions;

        return $this;
    }

    public function encrypt(string $data): string
    {
        if (0 >= $this->remainingEncryptions) {
            throw new Exception('the encryptor gave up mid-batch');
        }

        --$this->remainingEncryptions;

        return parent::encrypt($data);
    }
}
