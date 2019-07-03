<?php declare(strict_types=1);

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

/**
 * A wrapper around any openssl_* functions.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class OpensslWrapper
{
    /**
     * OpenSSL encrypt wrapper function
     *
     * @param string $data   Data to decrypt
     * @param string $method Cipher method to use
     * @param string $key    Key string
     * @param string $iv     Initialization vector
     * @param string $tag    AAD tag
     *
     * @return string
     */
    protected static function openssl_encrypt(string $data, string $method, string $key, string $iv, string &$tag): string
    {
        if (OpensslStatic::tagRequired($method)) {
            return \openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 4);
        } else {
            return \openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv);
        }
    }

    /**
     * OpenSSL decrypt wrapper function
     *
     * @param string $input  Data to decrypt
     * @param string $method Cipher method to use
     * @param string $key    Key string
     * @param string $iv     Initialization vector
     * @param string $tag    AAD authentication tag
     *
     * @return string
     */
    protected static function openssl_decrypt(string $input, string $method, string $key, string $iv, string $tag): string
    {
        if (OpensslStatic::tagRequired($method)) {
            return \openssl_decrypt($input, $method, $key, OPENSSL_RAW_DATA, $iv, $tag, '');
        } else {
            return \openssl_decrypt($input, $method, $key, OPENSSL_RAW_DATA, $iv);
        }
    }

    /**
     * Get IV size for specified CIPHER.
     *
     * @param string $cipher
     *
     * @return int
     */
    protected static function ivSize(string $cipher): int
    {
        $ret = \openssl_cipher_iv_length($cipher);

        return $ret;
    }

    /**
     * Get a correctly sized IV for the specified cipher
     *
     * @param string $cipher
     *
     * @return string
     * @throws \Exception
     */
    protected static function ivGenerate(string $cipher): string
    {
        $size = self::ivSize($cipher);

        if ($size === 0) {
            return '';
        }

        return \random_bytes($size);
    }

    /**
     * Determines if the provided cipher requires a tag
     *
     * @param string $cipher
     *
     * @return bool
     */
    protected static function tagRequired(string $cipher): bool
    {
        $cipher = strtolower($cipher);

        $needle_tips = [
            '-gcm',
            '-ccm',
        ];

        foreach ($needle_tips as $needle) {
            if (strpos($cipher, $needle)) {
                return true;
            }
        }

        return false;
    }
}
