<?php

/**
 * Aes.php
 * 
 * PHP version 7
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
     * Decrypt cyphertext
     * 
     * @param string $cyphertext Cyphertext to decrypt
     * @param string $password   Password that should be used to decrypt input data
     * @param int    $cost       Number of extra HMAC iterations to perform on key
     * 
     * @return string
     */
    public static function decrypt(string $cyphertext, string $password, int $cost = 0): string
    {
        // Find the IV at the beginning of the cypher text
        $ivr = Str::substr($cyphertext, 0, self::IVSIZE);

        // Derive key from password
        $key = self::key($password, $ivr, $cost, self::mode());

        // Gather the checksum portion of the cypher text
        $sum = Str::substr($cyphertext, self::IVSIZE, self::CKSIZE);

        // Gather message portion of cyphertext after iv and checksum
        $msg = Str::substr($cyphertext, self::IVSIZE + self::CKSIZE);

        // Calculate verification checksum
        $chk = self::checksum($msg, $ivr, $key, self::mode());

        // Verify HMAC before decrypting
        self::checksumVerify($chk, $sum);

        // Decrypt message and return
        return \openssl_decrypt($msg, static::CIPHER, $key, 1, $ivr);
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
    public static function encrypt(string $plaintext, string $password, int $cost = 0): string
    {
        // Generate IV of appropriate size.
        $ivr = \random_bytes(self::IVSIZE);

        // Derive key from password
        $key = self::key($password, $ivr, $cost, self::mode());

        // Encrypt the plaintext
        $msg = \openssl_encrypt($plaintext, static::CIPHER, $key, 1, $ivr);
        
        // If message could not be encrypted then throw an exception
        if ($msg === false) {
            throw new \exception('Could not encrypt the data.'); // @codeCoverageIgnore
        }

        // Create the cypher text prefix (iv + checksum)
        $prefix = $ivr . self::checksum($msg, $ivr, $key, self::mode());

        // Return prefix + cyphertext
        return $prefix . $msg;
    }
}
