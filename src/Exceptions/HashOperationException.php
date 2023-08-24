<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class HashOperationException extends Exception
{
    protected $message = 'Hash operation failed';
}
