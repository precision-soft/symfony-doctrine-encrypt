<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity;

use Doctrine\ORM\Mapping as ORM;

/** @internal */
#[ORM\Entity]
class EncryptedChild extends EncryptedParent {}
