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
 * An opaque 416 bit / 52 byte iterative hash function.
 *
 * 16 bytes => iv
 *  4 bytes => cost
 * 32 bytes => hmac
 *                  cost
 * ||||||||||||||||||||||||||||||||||||||||||||||||||||
 * iviviviviviviviv     machmachmachmachmachmachmachmac
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

        // Generate a deterministic hash of the password
        $hash = \hash_pbkdf2('sha256', $password, $salt, $cost, 0, true);

        // Return the salt + cost blob + hmac
        return $salt . self::costEncrypt($cost, $salt, $password) . $hash;
    }

    /**
     * Encrypts the cost value so that it can be added to the output hash discretely
     *
     * @param int    $cost
     * @param string $salt
     * @param string $password
     * @return string
     */
    private static function costEncrypt(int $cost, string $salt, string $password): string
    {
        $packed = pack('L*', $cost);

        return Otp::crypt($packed, ($password . $salt), 'sha256');
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
        $cost = Str::substr($hash, 16, 4);
        $cost = Otp::crypt($cost, ($password . $salt), 'sha256');
        $cost = unpack('L*', $cost)[1];

        // Return the boolean equivalence
        return Str::equal($hash, self::build($input, $password, $cost, $salt));
    }
}
