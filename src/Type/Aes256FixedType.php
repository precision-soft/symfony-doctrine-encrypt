<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Type;

class Aes256FixedType extends AbstractType
{
    protected static function getShortName(): string
    {
        return 'Aes256fixed';
    }
}
