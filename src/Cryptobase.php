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

class Cryptobase
{

    /**
     * Create a message authentication checksum.
     * 
     * @param string $cyphertext Cyphertext that needs a check sum.
     * @param string $iv         Initialization vector.
     * @param string $key        HMAC key
     * @param string $mode       Mcrypt mode
     * @param string $cipher     Mcrypt cipher
     * @param string $algo       Hashing algorithm to use for internal operations
     * 
     * @return string
     */
    protected static function _checksum($cyphertext, $iv, $key, $mode, $cipher, $algo)
    {
        // Prevent potentially large string concat by hmac-ing the cyphertext
        // by itself...
        $sum = hash_hmac($algo, $cyphertext, $key, true);

        // ... then hash other elements with previous hmac
        $sum = hash_hmac($algo, $sum . $iv . $mode . $cipher, $key, true);

        // Return an amount of hash bytes equal to the key size 
        return self::_hash($sum, strlen($key), $algo);
    }

    /**
     * This will normalize a hash to a certain length by extending it if
     * too long and truncating it if too short. This ensures that any
     * hash algo will work with any combination of other settings
     * 
     * @param string $hash Hash to be normalized
     * @param int    $size Size of the desired output hash, in bytes
     * @param string $algo Hashing algorithm to use for internal operations
     * 
     * @return string
     */
    protected static function _hash($hash, $size, $algo)
    {
        // Extend hash if too short
        while (strlen($hash) < $size) {
            $hash .= hash($algo, $hash, true);
        }

        // Return most significant bytes to a given size
        return substr($hash, 0, $size);
    }

    /**
     * Function which initializes common elements between encrypt and decrypt.
     * 
     * @param string $key    Key used to (en/de)crypt data.
     * @param string $cipher Mcrypt cipher
     * @param string $mode   Mcrypt mode
     * @param string $algo Hashing algorithm to use for internal operations
     * 
     * @return int Blocksize in bytes
     */
    protected static function _init(&$key, $cipher, $mode, $algo)
    {
        $key = self::_key($key, $cipher, $mode, $algo);

        if ($mode === null) {
            return 32;
        } else {
            return mcrypt_get_block_size($cipher, $mode);
        }
    }

    /**
     * Normalize encryption key via hashing to produce key that is equal
     * to block length.
     * 
     * @param string $key    Encryption key
     * @param string $cipher Mcrypt cipher
     * @param string $mode   Mcrypt block mode
     * @param string $algo   Hashing algorithm to use for internal operations
     * 
     * @return string
     */
    protected static function _key($key, $cipher, $mode, $algo)
    {
        if ($mode === null) {
            $keysize = 32;
        } else {
            // Get keysize so that a normalization hash can be performed on the key
            $keysize = mcrypt_get_key_size($cipher, $mode);
        }

        // Hash key
        $hash = hash($algo, $key, true);

        // Return hash normalized to key length
        return self::_hash($hash, $keysize, $algo);
    }

}
