<?php

/**
 * Openssl.php
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
 * Symmetric OpenSSL wrapper functions.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Openssl extends Cryptobase
{

    /**
     * AES-256 cipher idetifier that will be passed to openssl
     * 
     * @var string
     */
    const cipher = 'aes-256-cbc';
    
    /**
     * Size of initialization vector in bytes
     * 
     * @var int
     */
    const ivsize = 16;
    
    /**
     * Size of checksum in bytes
     * 
     * @var int
     */
    const cksize = 32;

    /**
     * Decrypt cyphertext
     * 
     * @param string $cyphertext Cyphertext to decrypt
     * @param string $password   Password that should be used to decrypt input data
     * @param int    $cost       Number of HMAC iterations to perform on key
     * 
     * @return string|boolean Returns false on checksum validation failure
     */
    public static function decrypt($cyphertext, $password, $cost = 0)
    {
        // Derive key from password
        $key = self::key($password, $cost);

        // Find the IV at the beginning of the cypher text
        $iv = self::substr($cyphertext, 0, self::ivsize);

        // Gather the checksum portion of the cypher text
        $chksum = self::substr($cyphertext, self::ivsize, self::cksize);

        // Gather message portion of cyphertext after iv and checksum
        $message = self::substr($cyphertext, self::ivsize + self::cksize);

        // Calculate verification checksum
        $verify = self::checksum($message, $iv, $key);

        // Verify HMAC before decrypting... return false if corrupt.
        if (!self::equals($verify, $chksum)) {
            return false;
        }

        // Decrypt message and return
        return openssl_decrypt($message, self::cipher, $key, 1, $iv);
    }

    /**
     * Encrypt plaintext
     * 
     * @param string $plaintext Plaintext string to encrypt.
     * @param string $password  Password used to encrypt data.
     * @param int    $cost      Number of HMAC iterations to perform on key
     * 
     * @return string 
     */
    public static function encrypt($plaintext, $password, $cost = 0)
    {
        // Derive key from password
        $key = self::key($password, $cost);

        // Generate IV of appropriate size.
        $iv = Random::get(self::ivsize);

        // Encrypt the plaintext
        $message = openssl_encrypt($plaintext, self::cipher, $key, 1, $iv);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . self::checksum($message, $iv, $key);

        // Return prefix + cyphertext
        return $prefix . $message;
    }

}
