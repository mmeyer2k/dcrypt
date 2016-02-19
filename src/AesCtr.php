<?php

/**
 * AesCtr.php
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
 * Symmetric AES-256-CTR encryption functions powered by OpenSSL.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class AesCtr extends Cryptobase
{

    /**
     * AES-256 cipher identifier that will be passed to openssl
     * 
     * @var string
     */
    const CIPHER = 'aes-256-ctr';

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
        // Find the IV at the beginning of the cypher text
        $iv = Str::substr($cyphertext, 0, self::IVSIZE);

        // Gather the key IV
        $keyiv = Str::substr($cyphertext, self::IVSIZE, self::IVSIZE);

        // Gather the checksum portion of the cypher text
        $chksum = Str::substr($cyphertext, self::IVSIZE * 2, self::CKSIZE);

        // Gather message portion of cyphertext after iv and checksum
        $message = Str::substr($cyphertext, self::IVSIZE * 2 + self::CKSIZE);

        // Derive key from password
        $key = self::key($password, $iv . $keyiv, $cost);

        // Calculate verification checksum
        $verify = self::checksum($message, $iv, $key);

        // Verify HMAC before decrypting
        if (!Str::equal($verify, $chksum)) {
            return static::invalidChecksum();
        }

        // Decrypt message with padding
        $padded = \openssl_decrypt($message, self::CIPHER, $key, 1, $iv);

        return Pkcs7::unpad($padded);
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
        // Generate IV of appropriate size.
        $iv = Random::get(self::IVSIZE);

        // Generage a second IV used only for the key. This helps to mitigate
        // the problem of encrypting twice with the same IV and key.
        $keyiv = Random::get(self::IVSIZE);

        // Derive key from password
        $key = self::key($password, $iv . $keyiv, $cost);

        $padded = Pkcs7::pad($plaintext, 16);

        // Encrypt the plaintext
        $message = \openssl_encrypt($padded, self::CIPHER, $key, 1, $iv);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . $keyiv . self::checksum($message, $iv, $key);

        // Return prefix + cyphertext
        return $prefix . $message;
    }

    /**
     * By default, \Dcrypt\Aes will will return false when the checksum is invalid.
     * Use AesExp to force an exception to be thrown instead.
     * 
     * @return false
     */
    private static function invalidChecksum()
    {
        return false;
    }

}
