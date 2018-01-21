<?php

/**
 * Cryptobase.php
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
 * Provides functionality common to Dcrypt's block ciphers.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Cryptobase
{
    /**
     * Create a message authentication checksum.
     *
     * @param string $cyphertext Cyphertext that needs a checksum.
     * @param string $iv         Initialization vector.
     * @param string $key        HMAC key
     * @param string $cipher     Cipher string
     * @param string $mode       Cipher mode string
     * @param string $algo       Hashing algorithm to use for internal operations
     *
     * @return string
     */
    protected static function checksum(string $cyphertext, string $iv, string $key, $cipher = 'rijndael-128', $mode = 'cbc', $algo = 'sha256'): string
    {
        // Prevent potentially large string concat by hmac-ing the cyphertext
        // by itself...
        $sum = \hash_hmac($algo, $cyphertext, $key, true);
        
        // If algo is unknown, throw an exception
        if ($sum === false) {
            throw new \exception("$algo is not supported by hash_hmac"); // @codeCoverageIgnore
        }

        // ... then hash other elements with previous hmac and return
        return \hash_hmac($algo, $sum . $iv . $mode . $cipher, $key, true);
    }

    /**
     * This will normalize a hash to a certain length by extending it if
     * too short and truncating it if too long. This ensures that any
     * hash algo will work with any combination of other settings. However,
     * it is probably best to make sure that the keysize and algo size
     * are identical so that the input hash passes through unchanged.
     *
     * @param string $hash Hash to be normalized
     * @param int    $size Size of the desired output hash, in bytes
     * @param string $algo Hashing algorithm to use for internal operations
     *
     * @return string
     */
    private static function hashNormalize(string $hash, int $size, string $algo): string
    {
        // Extend hash if too short
        while (Str::strlen($hash) < $size) {
            $hash .= \hash($algo, $hash, true);
        }

        // Truncate to specified number of bytes (if needed) and return
        return Str::substr($hash, 0, $size);
    }

    /**
     * Transform password into key and perform iterative HMAC (if specified)
     *
     * @param string $password Encryption key
     * @param string $iv       Initialization vector
     * @param int    $cost     Number of HMAC iterations to perform on key
     * @param string $cipher   Mcrypt cipher
     * @param string $mode     Mcrypt block mode
     * @param string $algo     Hashing algorithm to use for internal operations
     *
     * @return string
     */
    protected static function key(string $password, string $iv, $cost, $cipher = 'rijndael-128', $mode = 'cbc', $algo = 'sha256')
    {
        // This if statement allows the usage of the Openssl library without
        // the need to have the mcrypt plugin installed at all.
        if ($cipher === Aes::RIJNDA) {
            $keysize = 32;
        } else {
            $keysize = \mcrypt_get_key_size($cipher, $mode);
        }

        // Perform key derivation
        $key = Hash::ihmac($iv . $cipher . $mode, $password, $cost, $algo);

        // Return hash normalized to key length
        return self::hashNormalize($key, $keysize, $algo);
    }

    /**
     * Verify checksum during decryption step and throw error if mismatching.
     *
     * @param string $calculated
     * @param string $supplied
     */
    protected static function checksumVerify(string $calculated, string $supplied)
    {
        if (!Str::equal($calculated, $supplied)) {
            $e = 'Decryption can not proceed due to invalid cyphertext checksum.';
            throw new \InvalidArgumentException($e);
        }
    }
}
