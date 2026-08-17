<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

/**
 * Stands in for a consumer subclass, because every call inside the package goes through `getEncryptor()` and only a subclass observes `validate()`'s visibility.
 *
 * @internal
 */
final class ExtensionPointType extends Aes256Type
{
    public function validateThroughTheExtensionPoint(): void
    {
        $this->validate();
    }
}
