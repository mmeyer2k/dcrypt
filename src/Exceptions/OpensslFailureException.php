<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class OpensslFailureException extends Exception
{
    protected $message = 'Openssl could not perform the requested action';
}
