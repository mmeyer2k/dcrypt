<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class InternalOperationException extends Exception
{
    protected $message = 'An internal operation failed';
}
