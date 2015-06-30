<?php

/**
 * Support.php
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

/**
 * Provides numeric data conversion helper functions.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Support extends Str
{

    /**
     * Turns an integer into a 4 byte binary representation
     * 
     * @param int $dec Integer to convert to binary
     * 
     * @return string
     */
    protected static function dec2bin($dec)
    {
        return self::hex2bin(str_pad(dechex($dec), 8, '0', STR_PAD_LEFT));
    }

    /**
     * Reverses dec2bin
     * 
     * @param string $bin Binary string to convert to decimal
     * 
     * @return string
     */
    protected static function bin2dec($bin)
    {
        return hexdec(bin2hex($bin));
    }

    /**
     * An internal hex2bin implementation for PHP 5.3
     * 
     * @param string $hexstr
     * 
     * @return string
     */
    protected static function hex2bin($hexstr)
    {
        if (function_exists('hex2bin')) {
            return hex2bin($hexstr);
        }

        $n = strlen($hexstr);
        $sbin = '';
        $i = 0;
        while ($i < $n) {
            $a = substr($hexstr, $i, 2);
            $c = pack('H*', $a);
            if ($i == 0) {
                $sbin = $c;
            } else {
                $sbin.= $c;
            }
            $i+=2;
        }

        return $sbin;
    }

}
