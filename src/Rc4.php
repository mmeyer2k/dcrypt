<?php

/**
 * Rc4.php
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
 * An implementation of RC4 symmetric encryption.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     http://en.wikipedia.org/wiki/Stream_cipher
 * @link     https://en.wikipedia.org/wiki/RC4
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Rc4
{
    /**
     * Perform (en/de)cryption
     * 
     * @param string $str String to be encrypted
     * @param string $key Key to use for encryption
     * @return string
     */
    public static function crypt(string $str, string $key): string
    {
        $s = self::initializeState($key);
        $i = $j = 0;
        $res = '';
        $size = Str::strlen($str);
        for ($y = 0; $y < $size; $y++) {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            $x = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $x;
            $res .= $str[$y] ^ \chr($s[($s[$i] + $s[$j]) % 256]);
        }

        return $res;
    }

    /**
     * Create the initial byte matrix that will be used for swaps. This code
     * is identical between RC4 and Spritz.
     * 
     * @param string $key
     * @return array
     */
    protected static function initializeState(string $key): array
    {
        $s = \range(0, 255);
        $j = 0;
        foreach (\range(0, 255) as $i) {
            $j = ($j + $s[$i] + \ord($key[$i % Str::strlen($key)])) % 256;
            $x = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $x;
        }
        
        return $s;
    }
}
