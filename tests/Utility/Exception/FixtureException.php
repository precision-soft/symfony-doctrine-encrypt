<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility\Exception;

use RuntimeException;

/**
 * A fixture that finds itself in a state no test asked for; never a library failure, so never the library's exception.
 *
 * @internal
 */
final class FixtureException extends RuntimeException {}
