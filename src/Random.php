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
 */

namespace Dcrypt;

/**
 * Fail-safe wrapper for mcrypt_create_iv
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Random
{

    /**
     * Return random bytes
     * 
     * @param int $bytes
     * 
     * @return string
     */
    public static function get($bytes)
    {
        $e = 'Dcrypt failed to generate a random number';
        if (function_exists('mcrypt_create_iv')) {
            $ret = mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
            if ($ret === false) {
                throw new \exception($e); // @codeCoverageIgnore
            }
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $ret = openssl_random_pseudo_bytes($bytes, $secure);
            if ($secure === false) {
                throw new \exception($e); // @codeCoverageIgnore
            }
        } else {
            throw new \exception($e); // @codeCoverageIgnore
        }

        return $ret;
    }

}
