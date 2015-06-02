<?php

/**
 * Hashsize.php
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
 * Provides a look up table that correlates hash algorithms with their output 
 * size.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     http://en.wikipedia.org/wiki/Stream_cipher
 */
class HashSize
{

    private static $hashArray = array(
        'adler32' => 4,
        'crc32' => 4,
        'crc32b' => 4,
        'fnv132' => 4,
        'fnv164' => 8,
        'fnv1a32' => 4,
        'fnv1a64' => 8,
        'gost' => 32,
        'gost-crypto' => 32,
        'haval128,3' => 16,
        'haval128,4' => 16,
        'haval128,5' => 16,
        'haval160,3' => 20,
        'haval160,4' => 20,
        'haval160,5' => 20,
        'haval192,3' => 24,
        'haval192,4' => 24,
        'haval192,5' => 24,
        'haval224,3' => 28,
        'haval224,4' => 28,
        'haval224,5' => 28,
        'haval256,3' => 32,
        'haval256,4' => 32,
        'haval256,5' => 32,
        'joaat' => 4,
        'md2' => 16,
        'md4' => 16,
        'md5' => 16,
        'ripemd128' => 16,
        'ripemd160' => 20,
        'ripemd256' => 32,
        'ripemd320' => 40,
        'sha1' => 20,
        'sha224' => 28,
        'sha256' => 32,
        'sha384' => 48,
        'sha512' => 64,
        'snefru' => 32,
        'snefru256' => 32,
        'tiger128,3' => 16,
        'tiger128,4' => 16,
        'tiger160,3' => 20,
        'tiger160,4' => 20,
        'tiger192,3' => 24,
        'tiger192,4' => 24,
        'whirlpool' => 64,
    );

    /**
     * Quickly determine the length of the output of a given hash algorithm in bytes.
     * 
     * @param string $algo Name of algorithm to look up
     * 
     * @return int
     */
    public static function find($algo)
    {
        return self::$hashArray[$algo];
    }

}
