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
 * An opaque 512 bit iterative hash function.
 * 
 * 16 bytes => iv
 * 12 bytes => cost checksum
 *  4 bytes => cost
 * 32 bytes => hmac
 * 
 * ivivivivivivivivsssssssssssscosthmachmachmachmachmachmachmachmac
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
final class Hash extends Support
{

    const ALGO = 'sha256';

    /**
     * Internal function used to build the actual hash.
     *  
     * @param string       $input    Data to hash
     * @param string       $password Password to use in HMAC call
     * @param integer      $cost     Number of iterations to use
     * @param string|null  $salt     Initialization vector to use in HMAC calls
     * @return string
     */
    private static function build($input, $password, $cost, $salt = null)
    {
        // Generate salt if needed
        $salt = $salt === null ? Random::get(16) : $salt;

        // Verify and normalize cost value
        $cost = self::cost($cost);

        // Create key to use for hmac operations
        $key = \hash_hmac(self::ALGO, $salt, $password, true);

        // Perform hash iterations. Get a 32 byte output value
        $hash = self::ihmac($input, $key, $cost, self::ALGO);

        // Return the salt + cost blob + hmac
        return $salt . self::costHash($cost, $salt, $password) . $hash;
    }

    /**
     * Return a normalized cost value.
     * 
     * @param int $cost Number of iterations to use.
     * 
     * @return int
     */
    private static function cost($cost)
    {
        return $cost % \pow(2, 32);
    }

    private static function costHash($cost, $salt, $password)
    {
        // Hash and return first 12 bytes
        $hash = Str::substr(\hash_hmac(self::ALGO, $cost, $salt, true), 0, 12);

        // Convert cost to base 256 then encrypt with OTP stream cipher
        $cost = Otp::crypt(self::dec2bin($cost), $password);

        return $hash . $cost;
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
        $iter = abs($iter);
        
        for ($i = 0; $i <= $iter; $i++) {
            $data = \hash_hmac($algo, $data . $i . $iter, $key, true);
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
    public static function make($input, $password, $cost = 250000)
    {
        return self::build($input, $password, $cost, null);
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
        $salt = Str::substr($hash, 0, 16);

        // Get the encrypted cost bytes
        $cost = self::bin2dec(Otp::crypt(Str::substr($hash, 28, 4), $password));

        // Get the entire cost+hash blob for comparison
        $blob = Str::substr($hash, 16, 16);

        if (!Str::equal(self::costHash($cost, $salt, $password), $blob)) {
            return false;
        }

        // Return the boolean equivalence
        return Str::equal($hash, self::build($input, $password, $cost, $salt));
    }

}
