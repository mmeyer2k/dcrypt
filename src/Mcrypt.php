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
     * Decrypt cyphertext
     * 
     * @param string $cyphertext Cypher text to decrypt
     * @param string $password   Password that should be used to decrypt input data
     * @param int    $cost       Number of HMAC iterations to perform on key
     * @param string $cipher     Mcrypt cipher
     * @param string $mode       Mcrypt mode
     * @param string $algo       Hashing algorithm to use for internal operations
     * 
     * @return string|boolean Returns false on checksum validation failure
     */
    public static function decrypt($cyphertext, $password, $cost = 0, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC, $algo = 'sha256')
    {
        // Determine that size of the IV in bytes
        $ivsize = mcrypt_get_iv_size($cipher, $mode);

        // Find the IV at the beginning of the cypher text
        $iv = self::substr($cyphertext, 0, $ivsize);

        // Gather the checksum portion of the cypher text
        $chksum = self::substr($cyphertext, $ivsize, self::hashSize($algo));

        // Gather message portion of cyphertext after iv and checksum
        $message = self::substr($cyphertext, $ivsize + self::hashSize($algo));

        // Derive key from password
        $key = self::key($password, $cost, $cipher, $mode, $algo);

        // Calculate verification checksum
        $verify = self::checksum($message, $iv, $key, $cipher, $mode, $algo);

        // If chksum could not be verified return false
        if (!self::equals($verify, $chksum)) {
            return false;
        }

        // Decrypt, unpad, return
        return Pkcs7::unpad(mcrypt_decrypt($cipher, $key, $message, $mode, $iv));
    }

    /**
     * Encrypt plaintext
     * 
     * @param string $plaintext Plaintext string to encrypt
     * @param string $password  Key used to encrypt data
     * @param int    $cost      Number of HMAC iterations to perform on key
     * @param string $cipher    Mcrypt cipher
     * @param string $mode      Mcrypt mode
     * @param string $algo      Hashing algorithm to use for internal operations
     * 
     * @return string 
     */
    public static function encrypt($plaintext, $password, $cost = 0, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC, $algo = 'sha256')
    {

        // Determine the blocksize for the selected cipher/mode
        $blocksize = mcrypt_get_block_size($cipher, $mode);

        // Pad the input string
        $padded = Pkcs7::pad($plaintext, $blocksize);
        
        // Generate IV of appropriate size.
        $iv = Random::get(mcrypt_get_iv_size($cipher, $mode));
        
        // Derive key from password
        $key = self::key($password, $cost, $cipher, $mode, $algo);

        // Encrypt the plaintext
        $message = mcrypt_encrypt($cipher, $key, $padded, $mode, $iv);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . self::checksum($message, $iv, $key, $cipher, $mode, $algo);

        // Return prefix + cyphertext
        return $prefix . $message;
    }

}
