<?php

/**
 * OpensslWrapper.php
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

class OpensslWrapper
{

    /**
     * OpenSSL encrypt wrapper function
     *
     * @param string $inp Data to decrypt
     * @param string $mth Cipher method to use
     * @param string $key Key string
     * @param string $ivr Initialization vector
     * @return string
     */
    public static function encrypt(string $inp, string $mth, string $key, string $ivr): string
    {
        $ret = \openssl_encrypt($inp, $mth, $key, 1, $ivr);

        return self::returnOrException($ret);
    }

    /**
     * OpenSSL decrypt wrapper function
     *
     * @param string $inp Data to decrypt
     * @param string $mth Cipher method to use
     * @param string $key Key string
     * @param string $ivr Initialization vector
     * @return string
     */
    public static function decrypt(string $inp, string $mth, string $key, string $ivr): string
    {
        $ret = \openssl_decrypt($inp, $mth, $key, 1, $ivr);

        return self::returnOrException($ret);
    }

    /**
     * Throw an exception if openssl function returns false
     *
     * @param string|bool $data
     * @return string
     * @throws \Exception
     */
    private static function returnOrException($data): string
    {
        if ($data === false) {
            throw new \Exception('OpenSSL failed to encrypt/decrypt message.');
        }

        return $data;
    }

    /**
     * Get IV size for specified CIPHER.
     *
     * @param string $cipher
     * @return int
     * @throws \Exception
     */
    public static function ivsize(string $cipher): int
    {
        $ret = \openssl_cipher_iv_length($cipher);

        if ($ret === false) {
            throw new \Exception("Failed to determine correct IV size.");
        }

        return $ret;
    }
}
