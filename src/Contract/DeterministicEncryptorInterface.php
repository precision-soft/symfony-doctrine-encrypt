<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Contract;

/** Marker with no members: an implementer must produce identical ciphertext for identical plaintext, or a WHERE comparison against it can never match. */
interface DeterministicEncryptorInterface extends EncryptorInterface {}
