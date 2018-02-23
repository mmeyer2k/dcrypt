<?php

/**
 * Cryptobase.php
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
     * Create a message authentication checksum.
     *
     * @param string $cyphertext Cyphertext that needs a checksum.
     * @param string $iv         Initialization vector.
     * @param string $key        HMAC key
     * @param string $mode       Cipher mode (cbc, ctr)
     *
     * @return string
     */
    protected static function checksum(string $cyphertext, string $iv, string $key, string $mode): string
    {
        // Prevent potentially large string concat by hmac-ing the cyphertext
        // by itself...
        $sum = \hash_hmac(self::ALGO, $cyphertext, $key, true);
        
        // If algo is unknown, throw an exception
        if ($sum === false) {
            throw new \exception("$algo is not supported by hash_hmac"); // @codeCoverageIgnore
        }

        // ... then hash other elements with previous hmac and return
        return \hash_hmac(self::ALGO, $sum . $iv . $mode . self::RIJNDA, $key, true);
    }

    /**
     * Transform password into key and perform iterative HMAC (if specified)
     *
     * @param string $password Encryption key
     * @param string $iv       Initialization vector
     * @param int    $cost     Number of HMAC iterations to perform on key
     * @param string $mode     Cipher mode (cbc, ctr)
     *
     * @return string
     */
    protected static function key(string $password, string $iv, int $cost, string $mode): string
    {
        // Perform key derivation
        return Hash::ihmac($iv . self::RIJNDA . $mode, $password, $cost, self::ALGO);
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
    
    /**
     * Return the encryption mode string. "cbc" or "ctr"
     * 
     * @return string
     */
    protected static function mode(): string
    {
        return substr(static::CIPHER, -3);
    }
}
