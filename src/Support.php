<?php

/**
 * Support.php
 * 
 * PHP version 7
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt;

/**
 * Provides numeric data conversion helper functions.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Support
{
    /**
     * Turns an integer into a 4 byte binary representation
     * 
     * @param int $dec Integer to convert to binary
     * 
     * @return string
     */
    protected static function dec2bin(int $dec): string
    {
        return hex2bin(\str_pad(\dechex($dec), 8, '0', STR_PAD_LEFT));
    }

    /**
     * Reverses dec2bin
     * 
     * @param string $bin Binary string to convert to decimal
     * 
     * @return string
     */
    protected static function bin2dec(string $bin): string
    {
        return \hexdec(\bin2hex($bin));
    }
}
