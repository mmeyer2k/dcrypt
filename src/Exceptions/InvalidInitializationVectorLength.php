<?php

declare(strict_types=1);

namespace Dcrypt\Exceptions;

use Exception;

class InvalidInitializationVectorLength extends Exception
{
    protected $message = 'Given initialization vector was too small for cipher';
}
