<?php

/**
 * OpenSSL.php
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

class OpenSSL
{
    /**
     * OpenSSL encrypt wrapper function
     *
     * @param string $data
     * @param string $method
     * @param string $key
     * @param string $iv
     * @return string
     */
    protected static function openssl_encrypt(string $data, string $method, string $key, string $iv): string
    {
        $ret = \openssl_encrypt($data, $method, $key, 1, $iv);

        self::exceptionIfFalse($ret);

        return $ret;
    }

    /**
     * OpenSSL decrypt wrapper function
     *
     * @param string $data
     * @param string $method
     * @param string $key
     * @param string $iv
     * @return string
     */
    protected static function openssl_decrypt(string $data, string $method, string $key, string $iv): string
    {
        $ret = \openssl_decrypt($data, $method, $key, 1, $iv);

        self::exceptionIfFalse($ret);

        return $ret;
    }

    /**
     * Throw an exception if openssl function returns false
     *
     * @param string $data
     * @throws \Exception
     */
    private static function exceptionIfFalse(string $data)
    {
        if ($data === false) {
            throw new \Exception('OpenSSL failed to encrypt/decrypt message.');
        }
    }
}