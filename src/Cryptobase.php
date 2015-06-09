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
     * @param string $cipher     Mcrypt cipher
     * @param string $mode       Mcrypt mode
     * @param string $algo       Hashing algorithm to use for internal operations
     * 
     * @return string
     */
    protected static function _checksum($cyphertext, $iv, $key, $cipher = 'rijndael-128', $mode = 'cbc', $algo = 'sha256')
    {
        // Prevent potentially large string concat by hmac-ing the cyphertext
        // by itself...
        $sum = hash_hmac($algo, $cyphertext, $key, true);

        // ... then hash other elements with previous hmac and return
        return hash_hmac($algo, $sum . $iv . $mode . $cipher, $key, true);
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

        // Truncate to specified number of bytes (if needed) and return
        return substr($hash, 0, $size);
    }

    /**
     * Determine the length of the output of a given hash algorithm in bytes.
     * 
     * @param string $algo Name of algorithm to look up
     * 
     * @return int
     */
    protected static function _hashSize($algo)
    {
        return Strcmp::safeStrlen(hash($algo, 'hash me', true));
    }

    /**
     * Function which initializes common elements between encrypt and decrypt.
     * 
     * @param string $key    Key used to (en/de)crypt data.
     * @param int    $cost   Number of HMAC iterations to perform on key
     * @param string $cipher Mcrypt cipher
     * @param string $mode   Mcrypt mode
     * @param string $algo   Hashing algorithm to use for internal operations
     * 
     * @return int Blocksize in bytes
     */
    protected static function _init(&$key, $cost, $cipher = 'rijndael-128', $mode = 'cbc', $algo = 'sha256')
    {
        $key = self::_key($key, $cipher, $mode, $algo, $cost);

        if ($mode === 'cbc' && $cipher === 'rijndael-128') {
            return 16;
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
     * @param int    $cost   Number of HMAC iterations to perform on key
     * 
     * @return string
     */
    protected static function _key($key, $cipher, $mode, $algo, $cost)
    {
        if ($mode === 'cbc' && $cipher === 'rijndael-128') {
            $keysize = 32;
        } else {
            $keysize = mcrypt_get_key_size($cipher, $mode);
        }

        $hash = hash($algo, $key, true);

        if ($cost) {
            $hash = Hash::ihmac($hash, $key, $cost, $algo);
        }

        // Return hash normalized to key length
        return self::_hash($hash, $keysize, $algo);
    }

}
