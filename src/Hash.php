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
 * The hash class addresses some shortcomings in the password_hash function
 * built into PHP such as...
 *     - salt is known
 *     - rounds are known
 *     - password hashing scheme is obvious
 * 
 * hash::make() outputs a binary 512 bit string with the following format:
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

    const saltbytes = 31;
    const costbytes = 1;
    const coef = 32123;

    /**
     * Internal function used to build the actual hash.
     *  
     * @param string       $input    Data to hash.
     * @param string       $password Password to use in HMAC call.
     * @param string|null  $salt     Salt to use in HMAC call.
     * @param integer      $cost     Number of iterations to use.
     * 
     * @return string
     */
    private static function _build($input, $password, $salt = null, $cost = 10)
    {
        // If no salt was specified, generate a random 16 byte one. The salt 
        // will be provided during the verification step.
        if ($salt === null) {
            $salt = Random::get(self::saltbytes);
        }

        // Verify and normalize cost value
        $cost = self::_cost($cost);

        // Perform hash iterations. Get a 32 byte output value.
        $hash = self::ihmac($input . $salt, $password, $cost * self::coef, 'sha256');

        // Return the encrypted salt + encrypted cost value + hmac.
        return Otp::crypt($salt, $password) . Otp::crypt(chr($cost), $password) . $hash;
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
            $cost = 255;
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
    public static function make($input, $key, $cost = 10)
    {
        return self::_build($input, $key, null, $cost);
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
        $salt = Otp::crypt(self::substr($hash, 0, self::saltbytes), $password);

        // Get the encrypted cost byte
        $cost = self::substr($hash, self::saltbytes, self::costbytes);

        // Decrypt the cost value then convert to integer
        $cost = ord(Otp::crypt($cost, $password));

        // Return the boolean equivalence.
        return Str::equal($hash, self::_build($input, $password, $salt, $cost));
    }

}
