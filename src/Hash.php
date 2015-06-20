<?php

/**
 * Hash.php
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
 * \Dcrypt\Hash::make() outputs a binary 512 bit string with the following format:
 * 
 *              salt            cost              hash
 * [============================]|[===============================]
 *            31 byte          1 byte           32 byte
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Hash extends Str
{

    /**
     * Internal function used to build the actual hash.
     *  
     * @param string       $input    Data to hash.
     * @param string       $password Password to use in HMAC call.
     * @param string|null  $iv       Initialization vector to use in HMAC calls.
     * @param integer      $cost     Number of iterations to use.
     * 
     * @return string
     */
    private static function _build($input, $password, $iv = null, $cost = 10)
    {
        // Generate salt if needed
        if ($iv === null) {
            $iv = Random::get(31);
        }

        // Verify and normalize cost value
        $cost = self::_cost($cost);

        // Perform hash iterations. Get a 32 byte output value.
        $hash = self::ihmac($input, $password . $iv, $cost * 32123, 'sha256');

        // Return the encrypted salt + cost + hmac.
        return $iv . Otp::crypt(chr($cost), $password) . $hash;
    }

    /**
     * Return a normalized cost value.
     * 
     * @param int $cost Number of iterations to use.
     * 
     * @return int
     */
    private static function _cost($cost)
    {
        // Do bounds constraints
        if ($cost > 255) {
            $cost = 255; // @codeCoverageIgnore
        } elseif ($cost < 1) {
            $cost = 1;
        }

        // When all constraints are set, return cost
        return (int) $cost;
    }

    /**
     * Perform a raw iterative HMAC operation with a configurable algo.
     * 
     * This class always performs at least one hash to prevent the input from
     * being passed back unchanged if bad parameters are set.
     * 
     * @param string  $data Data to hash.
     * @param string  $key  Key to use to authenticate the hash.
     * @param integer $iter Number of times to iteratate the hash
     * @param string  $algo Name of algo (sha256 or sha512 recommended)
     * 
     * @return string
     */
    public static function ihmac($data, $key, $iter, $algo = 'sha256')
    {
        for ($i = 0; $i <= abs($iter); $i++) {
            $data = hash_hmac($algo, $data . $i . $iter, $key, true);
        }

        return $data;
    }

    /**
     * Hash an input string into a salted 512 byte hash.
     * 
     * @param string  $input    Data to hash.
     * @param string  $password HMAC validation password.
     * @param integer $cost     Cost value of the hash.
     * 
     * @return string
     */
    public static function make($input, $password, $cost = 10)
    {
        return self::_build($input, $password, null, $cost);
    }

    /**
     * Check the validity of a hash.
     * 
     * @param string $input    Input to test.
     * @param string $hash     Known hash to validate against.
     * @param string $password HMAC password to use during iterative hash. 
     * 
     * @return boolean
     */
    public static function verify($input, $hash, $password)
    {
        // Get the salt value from the decrypted prefix
        $iv = self::substr($hash, 0, 31);

        // Get the encrypted cost byte
        $cost = ord(Otp::crypt(self::substr($hash, 31, 1), $password));

        // Return the boolean equivalence.
        return Str::equal($hash, self::_build($input, $password, $iv, $cost));
    }

}
