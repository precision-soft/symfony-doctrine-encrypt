<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Type;

class Aes256Type extends AbstractType
{
    protected static function getShortName(): string
    {
        return 'Aes256';
    }
}
