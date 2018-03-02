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
 * An implementation of Spritz symmetric encryption.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     http://en.wikipedia.org/wiki/Stream_cipher
 * @link     https://en.wikipedia.org/wiki/RC4
 * @link     http://people.csail.mit.edu/rivest/pubs/RS14.pdf
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Spritz extends Rc4
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
        $i = $j = $k = $z = 0;
        $w = 1;
        $res = '';
        $size = Str::strlen($str);
        for ($y = 0; $y < $size; $y++) {
            $i = ($i + $w) % 256;
            $j = ($k + $s[($j + $s[$i]) % 256]) % 256;
            $k = ($i + $k + $s[$j]) % 256;
            $x = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $x;
            $z = $s[($j + $s[($i + $s[($z + $k) % 256]) % 256]) % 256];
            $res .= $str[$y] ^ \chr($z);
        }

        return $res;
    }
}
