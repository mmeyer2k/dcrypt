<?php declare(strict_types=1);

/**
 * InvalidKeyException.php
 *
 * PHP version 7
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt\Exceptions;

class InvalidKeyException extends \Exception
{
    const KEYLENGTH = 'Key must be at least 2048 bytes and base64 encoded';
    const KEYRANDOM = 'Key does not contain the minimum amount of entropy';
}