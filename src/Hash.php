<?php

/**
 * Hash.php
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
class Hash
{
    const ALGO = 'sha256';

    /**
     * Internal function used to build the actual hash.
     *
     * @param string      $input    Data to hash
     * @param string      $password Password to use in HMAC call
     * @param int         $cost     Number of iterations to use
     * @param string|null $salt     Initialization vector to use in HMAC calls
     * @return string
     */
    private static function build(string $input, string $password, int $cost, string $salt = null): string
    {
        // Generate salt if needed
        $salt = $salt ?? \random_bytes(16);

        // Verify and normalize cost value
        $cost = self::cost($cost);

        // Create key to use for hmac operations
        $key = self::hmac($salt, $password, self::ALGO);

        // Perform hash iterations. Get a 32 byte output value
        $hash = self::ihmac($input, $key, $cost, self::ALGO);

        // Return the salt + cost blob + hmac
        return $salt . self::costHash($cost, $salt, $password) . $hash;
    }

    /**
     * Return a normalized cost value.
     *
     * @param int $cost Number of iterations to use.
     * @return int
     */
    private static function cost(int $cost): int
    {
        return $cost % \pow(2, 32);
    }

    /**
     * Performs hashing functions
     *
     * @param int    $cost
     * @param string $salt
     * @param string $password
     * @return string
     */
    private static function costHash(int $cost, string $salt, string $password): string
    {
        // Hash and return first 12 bytes
        $hash = Str::substr(self::hmac($cost, $salt, self::ALGO), 0, 12);

        // Convert cost to base 256 then encrypt with OTP stream cipher
        $cost = Otp::crypt(self::dec2bin($cost), $password);

        return $hash . $cost;
    }

    /**
     * Perform a raw iterative HMAC operation with a configurable algo.
     *
     * @param string $data Data to hash.
     * @param string $key  Key to use to authenticate the hash.
     * @param int    $iter Number of times to iteratate the hash
     * @param string $algo Name of algo (sha256 or sha512 recommended)
     * @return string
     */
    public static function ihmac(string $data, string $key, int $iter, string $algo = 'sha256'): string
    {
        // Can't perform negative iterations
        $iter = \abs($iter);

        // Perform iterative hmac calls
        // Make sure $iter value of 0 is handled
        for ($i = 0; $i <= $iter; $i++) {
            $data = self::hmac($data . $i . $iter, $key, $algo);
        }

        return $data;
    }

    /**
     * Perform a single hmac iteration. This adds an extra layer of safety because hash_hmac can return false if algo
     * is not valid. Return type hint will throw an exception if this happens.
     *
     * @param string $data Data to hash.
     * @param string $key  Key to use to authenticate the hash.
     * @param string $algo Name of algo
     * @return string
     */
    public static function hmac(string $data, string $key, string $algo): string
    {
        return \hash_hmac($algo, $data, $key, true);
    }

    /**
     * Hash an input string into a salted 512 byte hash.
     *
     * @param string $input    Data to hash.
     * @param string $password HMAC validation password.
     * @param int    $cost     Cost value of the hash.
     * @return string
     */
    public static function make(string $input, string $password, int $cost = 250000): string
    {
        return self::build($input, $password, $cost, null);
    }

    /**
     * Check the validity of a hash.
     *
     * @param string $input    Input to test.
     * @param string $hash     Known hash to validate against.
     * @param string $password HMAC password to use during iterative hash.
     * @return boolean
     */
    public static function verify(string $input, string $hash, string $password): bool
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

    /**
     * Turns an integer into a 4 byte binary representation
     *
     * @param int $dec Integer to convert to binary
     * @return string
     */
    private static function dec2bin(int $dec): string
    {
        return \hex2bin(\str_pad(\dechex($dec), 8, '0', STR_PAD_LEFT));
    }

    /**
     * Reverses dec2bin
     *
     * @param string $bin Binary string to convert to decimal
     * @return string
     */
    private static function bin2dec(string $bin): string
    {
        return \hexdec(\bin2hex($bin));
    }
}
