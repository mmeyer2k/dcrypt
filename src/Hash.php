<?php declare(strict_types=1);

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
 * An opaque 480 bit / 60 byte iterative hash function.
 *
 * 16 bytes => iv
 *  8 bytes => cost hash
 *  4 bytes => cost
 * 32 bytes => hmac
 *
 * Byte format:
 *
 *                  costhash    hmachmachmachmachmachmachmachmac
 * |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
 * iviviviviviviviv         cost
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Hash
{
    const ALGO = 'sha256';

    /**
     * Internal function used to build the actual hash.
     *
     * @param string      $data Data to hash
     * @param string      $pass Password to use in HMAC call
     * @param int         $cost Number of iterations to use
     * @param string|null $salt Initialization vector to use in HMAC calls
     * @return string
     */
    private static function build(string $data, string $pass, int $cost, string $salt = null): string
    {
        // Generate salt if needed
        $salt = $salt ?? \random_bytes(16);

        // Generate a deterministic hash of the password
        $pkey = \hash_pbkdf2(self::ALGO, $pass, $salt, $cost, 0, true);

        // HMAC the input parameter with the generated key
        $hash = \hash_hmac(self::ALGO, $data, $pkey, true);

        // Covert cost value to byte array and encrypt
        $cost = self::costEncrypt($cost, $salt, $pass);

        // Create a hash of the cost to prevent DOS attacks caused by
        // flipping bits in the cost area of the blob and then requesting validation
        $chsh = self::costHash($cost, $pass);

        // Return the salt + cost + hmac as a single string
        return $salt . $chsh . $cost . $hash;
    }

    /**
     * Encrypts the cost value so that it can be added to the output hash discretely
     *
     * @param int    $cost
     * @param string $salt
     * @param string $pass
     * @return string
     */
    private static function costEncrypt(int $cost, string $salt, string $pass): string
    {
        // Pack the cost value into a 4 byte string
        $packed = pack('N', $cost);

        // Encrypt the string with the Otp stream cipher
        return Otp::crypt($packed, ($pass . $salt), self::ALGO);
    }

    /**
     * Decrypts the cost string back into an int
     *
     * @param string $pack
     * @param string $salt
     * @param string $pass
     * @return int
     */
    private static function costDecrypt(string $pack, string $salt, string $pass): int
    {
        // Decrypt the cost value stored in the 32bit int
        $pack = Otp::crypt($pack, ($pass . $salt), self::ALGO);

        // Unpack the value back to an integer and return to caller
        return unpack('N', $pack)[1];
    }

    /**
     * Hash an input string into a salted 52 bit hash.
     *
     * @param string $data Data to hash.
     * @param string $pass HMAC validation password.
     * @param int    $cost Cost value of the hash.
     * @return string
     */
    public static function make(string $data, string $pass, int $cost = 250000): string
    {
        return self::build($data, $pass, $cost, null);
    }

    /**
     * Check the validity of a hash.
     *
     * @param string $data Input to test.
     * @param string $hash Known hash to validate against.
     * @param string $pass HMAC password to use during iterative hash.
     * @return boolean
     */
    public static function verify(string $data, string $hash, string $pass): bool
    {
        // Get the salt value from the decrypted prefix
        $salt = Str::substr($hash, 0, 16);

        // Get the encrypted cost bytes out of the blob
        $chsh = Str::substr($hash, 16, 8);

        // Get the encrypted cost bytes out of the blob
        $cost = Str::substr($hash, 24, 4);

        // If the provided cost hash does not calculate to be the same as the one provided then consider the hash invalid.
        if ($chsh !== self::costHash($cost, $pass)) {
            return false;
        }

        // Decrypt the cost value stored in the 32bit int
        $cost = self::costDecrypt($cost, $salt, $pass);

        // Build a hash from the input for comparison
        $calc = self::build($data, $pass, $cost, $salt);

        // Return the boolean equivalence
        return Str::equal($hash, $calc);
    }

    /**
     * Returns the correct hash for an encrypted cost value.
     *
     * @param string $cost
     * @param string $pass
     * @return string
     */
    private static function costHash(string $cost, string $pass): string
    {
        return Str::substr(\hash_hmac(self::ALGO, $cost, $pass, true), 0, 8);
    }
}
