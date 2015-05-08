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
        $ret = mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
        
        if ($ret === false) {
            throw new \exception('Dcrypt failed to generate a random number');
        }
        
        return $ret;
    }

}
