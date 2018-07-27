<?php

/**
 * OpensslBridge.php
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
 * Provides functionality common to the dcrypt AES block ciphers. Extend this class to customize your cipher suite.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class OpensslBridge
{
    /**
     * This string is used when hashing to ensure cross compatibility between
     * dcrypt\mcrypt and dcrypt\aes. Since v7, this is only needed for backwards
     * compatibility with older versions
     */
    const RIJNDA = 'rijndael-128';

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
        $ivr = Str::substr($data, 0, self::ivsize());

        // Gather the checksum portion of the ciphertext
        $sum = Str::substr($data, self::ivsize(), self::cksize());

        // Gather message portion of ciphertext after iv and checksum
        $msg = Str::substr($data, self::ivsize() + self::cksize());

        // Derive key from password
        $key = self::key($pass, $ivr, $cost);

        // Calculate verification checksum
        $chk = self::checksum($msg, $ivr, $key);

        // Verify HMAC before decrypting
        self::checksumVerify($chk, $sum);

        // Decrypt message and return
        return OpensslWrapper::decrypt($msg, static::CIPHER, $key, $ivr);
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
        $ivr = \random_bytes(self::ivsize());

        // Derive key from password
        $key = self::key($pass, $ivr, $cost);

        // Encrypt the plaintext
        $msg = OpensslWrapper::encrypt($data, static::CIPHER, $key, $ivr);

        // Create the cypher text prefix (iv + checksum)
        $pre = $ivr . self::checksum($msg, $ivr, $key);

        // Return prefix + cyphertext
        return $pre . $msg;
    }

    /**
     * Create a message authentication checksum.
     *
     * @param string $data Ciphertext that needs a checksum.
     * @param string $iv   Initialization vector.
     * @param string $key  HMAC key
     * @return string
     */
    private static function checksum(string $data, string $iv, string $key): string
    {
        // Prevent multiple potentially large string concats by hmac-ing the input data
        // by itself first...
        $sum = Hash::hmac($data, $key, static::CHKSUM);

        // Then add the other input elements together before performing the final hash
        $sum = $sum . $iv . self::mode() . self::RIJNDA;

        // ... then hash other elements with previous hmac and return
        return Hash::hmac($sum, $key, static::CHKSUM);
    }

    /**
     * Transform password into key and perform iterative HMAC (if specified)
     *
     * @param string $pass Encryption key
     * @param string $iv   Initialization vector
     * @param int    $cost Number of HMAC iterations to perform on key
     * @return string
     */
    private static function key(string $pass, string $iv, int $cost): string
    {
        // Create the authentication string to be hashed
        $data = $iv . self::RIJNDA . self::mode();

        return Hash::ihmac($data, $pass, $cost, static::CHKSUM);
    }

    /**
     * Verify checksum during decryption step and throw error if mismatching.
     *
     * @param string $calculated
     * @param string $supplied
     * @throws \InvalidArgumentException
     */
    private static function checksumVerify(string $calculated, string $supplied)
    {
        if (!Str::equal($calculated, $supplied)) {
            $e = 'Decryption can not proceed due to invalid cyphertext checksum.';
            throw new \InvalidArgumentException($e);
        }
    }

    /**
     * Return the encryption mode string. This function is really only needed for backwards
     * compatibility.
     *
     * @return string
     */
    private static function mode(): string
    {
        // To prevent legacy blobs from not decoding, these ciphers (which were implemented before 8.3) have hard coded
        // return values. Luckily, this integrates gracefully with overloading.
        $legacy = [
            'bf-cbc' => 'cbc',
            'bf-ofb' => 'ofb',
            'aes-256-cbc' => 'cbc',
            'aes-256-ctr' => 'ctr',
        ];

        $cipher = \strtolower(static::CIPHER);

        if (isset($legacy[$cipher])) {
            return $legacy[$cipher];
        }

        return $cipher;
    }

    /**
     * Calculate checksum size
     *
     * @return int
     */
    private static function cksize(): int
    {
        return Str::hashSize(static::CHKSUM);
    }

    /**
     * Get IV size
     *
     * @return int
     */
    private static function ivsize(): int
    {
        return \openssl_cipher_iv_length(static::CIPHER);
    }
}
