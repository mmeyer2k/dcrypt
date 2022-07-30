<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class InvalidKeyEncodingException extends Exception
{
    protected $message = 'Key must be base64 encoded';
}
