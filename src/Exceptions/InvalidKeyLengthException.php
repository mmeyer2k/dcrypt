<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class InvalidKeyLengthException extends Exception
{
    protected $message = 'Key must be at least 32 bytes';
}
