<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Contract;

/**
 * marker interface for encryptors that produce identical ciphertext for identical plaintext.
 *
 * required for use with EntityService::setEncryptedParameter() since non-deterministic encryptors
 * would yield different ciphertexts on each call, causing generated WHERE clauses to never match.
 */
interface DeterministicEncryptorInterface extends EncryptorInterface {}
