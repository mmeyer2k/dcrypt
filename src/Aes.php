<?php

/**
 * Aes.php
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

use Symfony\Component\Security\Core\Util\StringUtils;

/**
 * Symmetric AES encryption implementation wrapper functions.
 * 
 * Features:
 *     - PKCS #7 padding of messages
 *     - random IV selection
 *     - checksum validation with SHA-256 HMAC by default
 *     - tested to be compatible with many ciphers, modes and hashing algorithms.
 *     - highly customizable, but default options are most secure
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Aes
{

    /**
     * Create a message authentication checksum.
     * 
     * @param string $cyphertext Cyphertext that needs a check sum.
     * @param string $iv         Initialization vector.
     * @param string $key        Encryption key that will act as an HMAC 
     *                           verification signature.
     * @param string $mode       Mcrypt mode
     * @param string $cipher     Mcrypt cipher
     * @param string $algo       Hashing algorithm to use for internal operations
     * 
     * @return string
     */
    private static function _checksum($cyphertext, $iv, $key, $mode, $cipher, $algo)
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
     * Decrypt data that was generated with the Aes::encrypt() method.
     * 
     * @param string $cyphertext Cypher text to decrypt
     * @param string $key        Key that should be used to decrypt input data
     * @param string $mode       Mcrypt mode
     * @param string $cipher     Mcrypt cipher
     * @param string $algo       Hashing algorithm to use for internal operations
     * 
     * @return string|boolean Returns false on checksum validation failure
     */
    public static function decrypt($cyphertext, $key, $mode = MCRYPT_MODE_CBC, $cipher = MCRYPT_RIJNDAEL_128, $algo = 'sha256')
    {
        // Normalize (de/en)cryption key (by-ref) and return block size
        self::_init($key, $cipher, $mode, $algo);

        // Determine that size of the IV in bytes
        $ivsize = mcrypt_get_iv_size($cipher, $mode);

        // Find the IV at the beginning of the cypher text
        $iv = substr($cyphertext, 0, $ivsize);

        // Gather the checksum portion of the cypher text
        $chksum = substr($cyphertext, $ivsize, strlen($key));

        // Gather message portion of cyphertext after iv and checksum
        $message = substr($cyphertext, $ivsize + strlen($key));

        // Calculate verification checksum
        $verify = self::_checksum($message, $iv, $key, $mode, $cipher, $algo);

        // If chksum could not be verified return false
        if (!StringUtils::equals($verify, $chksum)) {
            return false;
        }

        // Decrypt, unpad, return
        return Pkcs7::unpad(mcrypt_decrypt($cipher, $key, $message, $mode, $iv));
    }

    /**
     * Encrypt plaintext data.
     * 
     * @param string $plaintext Plaintext string to encrypt.
     * @param string $key       Key used to encrypt data.
     * @param string $mode      Mcrypt mode
     * @param string $cipher    Mcrypt cipher
     * @param string $algo      Hashing algorithm to use for internal operations
     * 
     * @return string 
     */
    public static function encrypt($plaintext, $key, $mode = MCRYPT_MODE_CBC, $cipher = MCRYPT_RIJNDAEL_128, $algo = 'sha256')
    {
        // Normalize (de/en)cryption key (by-ref) and return block size
        $blocksize = self::_init($key, $cipher, $mode, $algo);

        // Generate IV of appropriate size.
        $iv = Random::get(mcrypt_get_iv_size($cipher, $mode));

        // Pad the input string
        $padded = Pkcs7::pad($plaintext, $blocksize);

        // Encrypt the plaintext
        $message = mcrypt_encrypt($cipher, $key, $padded, $mode, $iv);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . self::_checksum($message, $iv, $key, $mode, $cipher, $algo);

        // Return prefix + cyphertext
        return $prefix . $message;
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
    private static function _hash($hash, $size, $algo)
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
    private static function _init(&$key, $cipher, $mode, $algo)
    {
        $key = self::_key($key, $cipher, $mode, $algo);

        return mcrypt_get_block_size($cipher, $mode);
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
    private static function _key($key, $cipher, $mode, $algo)
    {
        // Get keysize so that a normalization hash can be performed on the key
        $keysize = mcrypt_get_key_size($cipher, $mode);

        // Hash key
        $hash = hash($algo, $key, true);

        // Return hash normalized to key length
        return self::_hash($hash, $keysize, $algo);
    }

}
