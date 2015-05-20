<?php

/**
 * Aes.php
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt;

class Aes extends Cryptobase
{

    private static function _bestLibrary()
    {
        return function_exists('openssl_encrypt') ? 'Openssl' : 'Mcrypt';
    }

    public static function decrypt($cyphertext, $key)
    {
        $class = self::_bestLibrary();
        return $class::decrypt($cyphertext, $key);
    }

    public static function encrypt($plaintext, $key)
    {
        $class = self::_bestLibrary();
        return $class::decrypt($plaintext, $key);
    }

}
