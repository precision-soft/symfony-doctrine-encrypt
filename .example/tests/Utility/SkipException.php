<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Test\Utility;

use PrecisionSoft\Doctrine\Encrypt\Example\Exception\Exception;

/**
 * Means "the database is absent"; the suite runs with `--fail-on-skipped`, so it is a failure in CI and a skip on a laptop without the containers.
 *
 * @internal
 */
final class SkipException extends Exception {}
