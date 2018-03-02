<?php

/**
 * Aes.php
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
 * Provides functionality common to the dcrypt AES block ciphers.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Aes extends OpenSsl
{
    /**
     * This string is used when hashing to ensure cross compatibility between
     * dcrypt\mcrypt and dcrypt\aes. Since v7, this is only needed for backwards
     * compatibility with older versions
     */
    const RIJNDA = 'rijndael-128';

    /**
     * Hardcoded hashing algo string.
     */
    const ALGO = 'sha256';

    /**
     * Size of initialization vector in bytes
     *
     * @var int
     */
    const IVSIZE = 16;

    /**
     * Size of checksum in bytes
     *
     * @var int
     */
    const CKSIZE = 32;

    /**
     * Create a message authentication checksum.
     *
     * @param string $data Ciphertext that needs a checksum.
     * @param string $iv   Initialization vector.
     * @param string $key  HMAC key
     * @param string $mode Cipher mode (cbc, ctr)
     * @return string
     */
    protected static function checksum(string $data, string $iv, string $key, string $mode): string
    {
        // Prevent potentially multiple large string concats by hmac-ing the input data
        // by itself first...
        $sum = Hash::hmac($data, $key, self::ALGO);

        // Add the other elements together before performing the final hash
        $sum = $sum . $iv . $mode . self::RIJNDA;

        // ... then hash other elements with previous hmac and return
        return Hash::hmac($sum, $key, self::ALGO);
    }

    /**
     * Transform password into key and perform iterative HMAC (if specified)
     *
     * @param string $password Encryption key
     * @param string $iv       Initialization vector
     * @param int    $cost     Number of HMAC iterations to perform on key
     * @param string $mode     Cipher mode (cbc, ctr)
     * @return string
     */
    protected static function key(string $password, string $iv, int $cost, string $mode): string
    {
        return Hash::ihmac($iv . self::RIJNDA . $mode, $password, $cost, self::ALGO);
    }

    /**
     * Verify checksum during decryption step and throw error if mismatching.
     *
     * @param string $calculated
     * @param string $supplied
     * @throws \InvalidArgumentException
     */
    protected static function checksumVerify(string $calculated, string $supplied)
    {
        if (!Str::equal($calculated, $supplied)) {
            $e = 'Decryption can not proceed due to invalid cyphertext checksum.';
            throw new \InvalidArgumentException($e);
        }
    }

    /**
     * Return the encryption mode string. "cbc" or "ctr"
     *
     * @return string
     */
    protected static function mode(): string
    {
        return Str::substr(static::CIPHER, -3);
    }
}
