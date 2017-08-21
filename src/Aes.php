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

/**
 * Symmetric AES-256-CBC encryption functions powered by OpenSSL.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Aes extends Cryptobase
{

    /**
     * AES-256 cipher identifier that will be passed to openssl
     * 
     * @var string
     */
    const CIPHER = 'aes-256-cbc';

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
     * This string is used when hashing to ensure cross compatibility between
     * dcrypt\mcrypt and dcrypt\aes.
     */
    const RIJNDA = 'rijndael-128';

    /**
     * Decrypt cyphertext
     * 
     * @param string $cyphertext Cyphertext to decrypt
     * @param string $password   Password that should be used to decrypt input data
     * @param int    $cost       Number of extra HMAC iterations to perform on key
     * 
     * @return string
     */
    public static function decrypt($cyphertext, $password, $cost = 0)
    {
        // Find the IV at the beginning of the cypher text
        $iv = Str::substr($cyphertext, 0, self::IVSIZE);

        // Gather the checksum portion of the cypher text
        $chksum = Str::substr($cyphertext, self::IVSIZE, self::CKSIZE);

        // Gather message portion of cyphertext after iv and checksum
        $message = Str::substr($cyphertext, self::IVSIZE + self::CKSIZE);

        // Derive key from password
        $key = self::key($password, $iv, $cost, self::RIJNDA, self::mode());

        // Calculate verification checksum
        $verify = self::checksum($message, $iv, $key, self::RIJNDA, self::mode());

        // Verify HMAC before decrypting
        self::checksumVerify($verify, $chksum);

        // Decrypt message and return
        return \openssl_decrypt($message, static::CIPHER, $key, 1, $iv);
    }

    /**
     * Encrypt plaintext
     * 
     * @param string $plaintext Plaintext string to encrypt.
     * @param string $password  Password used to encrypt data.
     * @param int    $cost      Number of extra HMAC iterations to perform on key
     * 
     * @return string 
     */
    public static function encrypt($plaintext, $password, $cost = 0)
    {
        // Generate IV of appropriate size.
        $iv = Random::bytes(self::IVSIZE);

        // Derive key from password
        $key = self::key($password, $iv, $cost, self::RIJNDA, self::mode());

        // Encrypt the plaintext
        $message = \openssl_encrypt($plaintext, static::CIPHER, $key, 1, $iv);
        
        // If message could not be encrypted then throw an exception
        if ($message === false) {
            throw new \exception('Could not encrypt the data.');
        }

        // Create the cypher text prefix (iv + checksum)
        $prefix = $iv . self::checksum($message, $iv, $key, self::RIJNDA, self::mode());

        // Return prefix + cyphertext
        return $prefix . $message;
    }

    /**
     * Return the encryption mode string. "cbc" or "ctr"
     * 
     * @return string
     */
    protected static function mode()
    {
        return substr(static::CIPHER, -3);
    }

}
