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
     * Decrypt cyphertext
     *
     * @param string $data Cyphertext to decrypt
     * @param string $pass Password that should be used to decrypt input data
     * @return string
     */
    public static function decrypt(string $data, string $pass): string
    {
        // Calculate the hash checksum size in bytes for the specified algo
        $hsz = Str::hashSize(static::CHKSUM);

        // Ask openssl for the IV size needed for specified cipher
        $isz = OpensslWrapper::ivsize(static::CIPHER);

        // Find the IV at the beginning of the cypher text
        $ivr = Str::substr($data, 0, $isz);

        // Gather the checksum portion of the ciphertext
        $sum = Str::substr($data, $isz, $hsz);

        // Gather the iterations portion of the cipher text as packed/encrytped unsigned long
        $itr = Str::substr($data, $isz + $hsz, 4);

        // Gather message portion of ciphertext after iv and checksum
        $msg = Str::substr($data, $isz + $hsz + 4);

        // Decrypt and unpack the cost parameter to match what was used during encryption
        $cost = \unpack('N', $itr ^ \hash_hmac(static::CHKSUM, $ivr, $pass, true))[1];

        // Derive key from password
        $key = \hash_pbkdf2(static::CHKSUM, ($pass . static::CIPHER), $ivr, $cost, 0, true);

        // Calculate verification checksum
        $chk = \hash_hmac(static::CHKSUM, $msg, $key, true);

        // Verify HMAC before decrypting
        if (!Str::equal($chk, $sum)) {
            throw new \InvalidArgumentException('Decryption can not proceed due to invalid cyphertext checksum.');
        }

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
    public static function encrypt(string $data, string $pass, int $cost = 1): string
    {
        // Generate IV of appropriate size.
        $ivr = \random_bytes(OpensslWrapper::ivsize(static::CIPHER));

        // Derive key from password with hash_pbkdf2 function.
        // Append CIPHER to password beforehand so that cross-method decryptions will fail at checksum step
        $key = \hash_pbkdf2(static::CHKSUM, ($pass . static::CIPHER), $ivr, $cost, 0, true);

        // Encrypt the plaintext data
        $msg = OpensslWrapper::encrypt($data, static::CIPHER, $key, $ivr);

        // Convert cost integer into 4 byte string and XOR it with a newly derived key
        $itr = \pack('N', $cost) ^ \hash_hmac(static::CHKSUM, $ivr, $pass, true);

        // Generate the ciphertext checksum to prevent bit tampering
        $chk = \hash_hmac(static::CHKSUM, $msg, $key, true);

        // Return iv + checksum + iterations + cyphertext
        return $ivr . $chk . $itr . $msg;
    }
}
