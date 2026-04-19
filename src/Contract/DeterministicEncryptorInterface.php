<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Contract;

/** @info marker: implementers must produce identical ciphertext for identical plaintext so the value is usable in WHERE comparisons */
interface DeterministicEncryptorInterface extends EncryptorInterface {}
