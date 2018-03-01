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
        return \openssl_encrypt($data, $method, $key, 1, $iv);
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
        return \openssl_decrypt($data, $method, $key, 1, $iv);
    }
}