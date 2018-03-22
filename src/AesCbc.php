<?php

/**
 * AesCbc.php
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
class AesCbc extends Aes
{
    /**
     * AES-256 cipher identifier that will be passed to openssl
     *
     * @var string
     */
    const CIPHER = 'aes-256-cbc';

    /**
     * Decrypt cyphertext
     *
     * @param string $data Cyphertext to decrypt
     * @param string $pass Password that should be used to decrypt input data
     * @param int    $cost Number of extra HMAC iterations to perform on key
     * @return string
     */
    public static function decrypt(string $data, string $pass, int $cost = 0): string
    {
        // Find the IV at the beginning of the cypher text
        $ivr = Str::substr($data, 0, self::IVSIZE);

        // Gather the checksum portion of the ciphertext
        $sum = Str::substr($data, self::IVSIZE, self::CKSIZE);

        // Gather message portion of ciphertext after iv and checksum
        $msg = Str::substr($data, self::IVSIZE + self::CKSIZE);

        // Derive key from password
        $key = self::key($pass, $ivr, $cost, self::mode());

        // Calculate verification checksum
        $chk = self::checksum($msg, $ivr, $key, self::mode());

        // Verify HMAC before decrypting
        self::checksumVerify($chk, $sum);

        // Decrypt message and return
        return self::opensslDecrypt($msg, static::CIPHER, $key, $ivr);
    }

    /**
     * Encrypt plaintext
     *
     * @param string $data Plaintext string to encrypt.
     * @param string $pass Password used to encrypt data.
     * @param int    $cost Number of extra HMAC iterations to perform on key
     * @return string
     */
    public static function encrypt(string $data, string $pass, int $cost = 0): string
    {
        // Generate IV of appropriate size.
        $ivr = \random_bytes(self::IVSIZE);

        // Derive key from password
        $key = self::key($pass, $ivr, $cost, self::mode());

        // Encrypt the plaintext
        $msg = self::opensslEncrypt($data, static::CIPHER, $key, $ivr);

        // Create the cypher text prefix (iv + checksum)
        $prefix = $ivr . self::checksum($msg, $ivr, $key, self::mode());

        // Return prefix + cyphertext
        return $prefix . $msg;
    }
}
