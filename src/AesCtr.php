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
class AesCtr extends Aes
{

    /**
     * AES-256 cipher identifier that will be passed to openssl
     * 
     * @var string
     */
    const CIPHER = 'aes-256-ctr';

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
        return Pkcs7::unpad(parent::decrypt($password, $cyphertext, $cost));
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
        return parent::encrypt(Pkcs7::pad($plaintext), $password, $cost);
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
