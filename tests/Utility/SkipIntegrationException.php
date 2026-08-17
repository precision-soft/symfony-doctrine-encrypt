<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility;

use RuntimeException;

/**
 * Means "the database is absent", which must become a skip and never a failure.
 *
 * @internal
 */
final class SkipIntegrationException extends RuntimeException {}
