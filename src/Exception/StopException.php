<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Exception;

/**
 * @info must always be caught inside this package — it is an internal control-flow signal, not a real error
 * @internal
 */
class StopException extends Exception {}
