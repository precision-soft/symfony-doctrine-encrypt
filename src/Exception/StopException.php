<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Exception;

/**
 * used to stop a flow
 * if thrown should also always be caught in this package.
 *
 * @internal
 */
final class StopException extends Exception {}
