<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Exception;

/**
 * used to stop an internal flow, if thrown, it should always be caught within this package.
 *
 * @internal
 */
final class StopException extends Exception {}
