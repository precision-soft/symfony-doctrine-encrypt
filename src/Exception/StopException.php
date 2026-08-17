<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Exception;

/**
 * A control-flow signal rather than a failure, so it must never be allowed to escape this package.
 *
 * @internal
 */
class StopException extends Exception {}
