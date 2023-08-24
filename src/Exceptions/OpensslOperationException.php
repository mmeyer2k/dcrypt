<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class OpensslOperationException extends Exception
{
    protected $message = 'Openssl operation failed';
}