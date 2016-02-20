<?php

/**
 * Random.php
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt
 */

namespace Dcrypt;

/**
 * Fail-safe wrapper for mcrypt_create_iv (preferably) and
 * openssl_random_pseudo_bytes (fallback).
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/class-Dcrypt.Random.html
 */
final class Random
{

    /**
     * Get random bytes from Mcrypt
     * 
     * @param int $bytes Number of bytes to get
     * 
     * @return string
     */
    private static function fromMcrypt($bytes)
    {
        $ret = \mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);

        if ($ret === false) {
            self::toss(); // @codeCoverageIgnore
        }

        return $ret;
    }

    /**
     * Return securely generated random bytes.
     * 
     * @param int  $bytes  Number of bytes to get
     * 
     * @return string
     */
    public static function bytes($bytes)
    {
        if (\function_exists('random_bytes')) {
            return \random_bytes($bytes);
        } elseif (\function_exists('mcrypt_create_iv')) {
            return self::fromMcrypt($bytes);
        }
        
        self::toss();
    }

    /*
     * Throw an error when a failure occurs.
     */

    private static function toss()
    {
        // @codeCoverageIgnoreStart
        $e = 'Dcrypt failed to generate a random number';
        throw new \exception($e);
        // @codeCoverageIgnoreEnd
    }

}
