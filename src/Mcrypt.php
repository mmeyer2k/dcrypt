<?php

/**
 * Mcrypt.php
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
 * Symmetric Mcrypt wrapper functions.
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
class Mcrypt extends Cryptobase
{

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
        // Normalize (de/en)cryption key (by-ref)
        self::_init($key, $cipher, $mode, $algo);

        // Determine that size of the IV in bytes
        $ivsize = mcrypt_get_iv_size($cipher, $mode);

        // Find the IV at the beginning of the cypher text
        $iv = substr($cyphertext, 0, $ivsize);

        // Gather the checksum portion of the cypher text
        $chksum = substr($cyphertext, $ivsize, self::_hashSize($algo));

        // Gather message portion of cyphertext after iv and checksum
        $message = substr($cyphertext, $ivsize + self::_hashSize($algo));

        // Calculate verification checksum
        $verify = self::_checksum($message, $iv, $key, $cipher, $mode, $algo);

        // If chksum could not be verified return false
        if (!Strcmp::equals($verify, $chksum)) {
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
        $prefix = $iv . self::_checksum($message, $iv, $key, $cipher, $mode, $algo);

        // Return prefix + cyphertext
        return $prefix . $message;
    }

}
