<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class InvalidChecksumException extends Exception
{
    protected $message = 'Invalid ciphertext checksum';
}
