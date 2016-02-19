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
 *     - checksum validation with HMAC
 *     - tested to be compatible with many ciphers, modes and hashing algorithms.
 *     - highly customizable, but default options are most secure
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
final class Mcrypt extends Cryptobase
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
        $ivsize = \mcrypt_get_iv_size($cipher, $mode);

        // Find the IV at the beginning of the cypher text
        $iv = Str::substr($cyphertext, 0, $ivsize);

        // Gather the checksum portion of the cypher text
        $chksum = Str::substr($cyphertext, $ivsize, self::hashSize($algo));

        // Gather message portion of cyphertext after iv and checksum
        $message = Str::substr($cyphertext, $ivsize + self::hashSize($algo));

        // Derive key from password
        $key = self::key($password, $iv, $cost, $cipher, $mode, $algo);

        // Calculate verification checksum
        $verify = self::checksum($message, $iv, $key, $cipher, $mode, $algo);

        // If checksum could not be verified return false
        if (!Str::equal($verify, $chksum)) {
            return false;
        }

        // Decrypt unpad return
        return Pkcs7::unpad(\mcrypt_decrypt($cipher, $key, $message, $mode, $iv));
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
        // Pad the input string to a multiple of block size
        $padded = Pkcs7::pad($plaintext, \mcrypt_get_block_size($cipher, $mode));

        // Generate IV of appropriate size
        $iv = Random::bytes(\mcrypt_get_iv_size($cipher, $mode));

        // Derive key from password
        $key = self::key($password, $iv, $cost, $cipher, $mode, $algo);

        // Encrypt the plaintext
        $message = \mcrypt_encrypt($cipher, $key, $padded, $mode, $iv);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . self::checksum($message, $iv, $key, $cipher, $mode, $algo);

        // Return prefix + cyphertext
        return $prefix . $message;
    }

}
