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

    const cipher = 'aes-256-cbc';
    const algo = 'sha256';

    /**
     * Decrypt data that was generated with the Aes::encrypt() method.
     * 
     * @param string $cyphertext Cypher text to decrypt
     * @param string $key        Key that should be used to decrypt input data
     * 
     * @return string|boolean Returns false on checksum validation failure
     */
    public static function decrypt($cyphertext, $key)
    {
        // Normalize (de/en)cryption key (by-ref)
        self::_init($key, self::cipher, null, self::algo);

        // Determine that size of the IV in bytes
        $ivsize = openssl_cipher_iv_length(self::cipher);

        // Find the IV at the beginning of the cypher text
        $iv = substr($cyphertext, 0, $ivsize);

        // Gather the checksum portion of the cypher text
        $chksum = substr($cyphertext, $ivsize, strlen($key));

        // Gather message portion of cyphertext after iv and checksum
        $message = substr($cyphertext, $ivsize + strlen($key));

        // Calculate verification checksum
        $verify = self::_checksum($message, $iv, $key, null, self::cipher, self::algo);

        // If chksum could not be verified return false
        if (!Strcmp::equals($verify, $chksum)) {
            return false;
        }

        // Decrypt, unpad, return
        return openssl_decrypt($message, self::cipher, $key, 1, $iv);
    }

    /**
     * Encrypt plaintext data.
     * 
     * @param string $plaintext Plaintext string to encrypt.
     * @param string $key       Key used to encrypt data.
     * 
     * @return string 
     */
    public static function encrypt($plaintext, $key)
    {
        // Normalize (de/en)cryption key (by-ref)
        self::_init($key, self::cipher, null, self::algo);

        // Generate IV of appropriate size.
        $iv = Random::get(openssl_cipher_iv_length(self::cipher));

        // Encrypt the plaintext
        $message = openssl_encrypt($plaintext, self::cipher, $key, 1, $iv);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . self::_checksum($message, $iv, $key, null, self::cipher, self::algo);

        // Return prefix + cyphertext
        return $prefix . $message;
    }

}
