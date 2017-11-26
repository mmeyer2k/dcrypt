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
        
        self::toss(); // @codeCoverageIgnore
    }

    /**
     * Throw an error when a failure occurs.
     * 
     * @codeCoverageIgnore
     */
    private static function toss()
    {
        $e = 'Dcrypt failed to generate a random number';
        throw new \exception($e);
    }
    
    /**
     * Deterministic seeded array shuffle function.
     *
     * @param array  $array
     * @param string $seed
     * @param int    $mode
     * 
     * @return array
     */
    public static function shuffle($array, $seed, $mode = MT_RAND_PHP)
    {
        $count = count($array);

        $range = range(0, count($array) - 1);

        // Hash the seed and extract bytes to make integer with
        $seed = substr(hash('sha256', $seed, true), 0, PHP_INT_SIZE);

        // Convert bytes to int
        $seed = unpack("L", $seed);

        mt_srand($seed[1], $mode);

        foreach ($range as $a) {
            $b = mt_rand(0, $count - 1);

            $v = $array[$a];

            $array[$a] = $array[$b];

            $array[$b] = $v;
        }

        return $array;
    }
}
