<?php

declare(strict_types=1);

/**
 * OpensslWrapper.php.
 *
 * PHP version 7
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt;

/**
 * A wrapper around any openssl_* functions.
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class OpensslWrapper
{
    /**
     * OpenSSL encrypt wrapper function.
     *
     * @param string $data   Data to decrypt
     * @param string $cipher Cipher method to use
     * @param string $key    Key string
     * @param string $iv     Initialization vector
     * @param string $tag    AAD tag
     *
     * @return string
     */
    protected static function opensslEncrypt(
        string $data,
        string $cipher,
        string $key,
        string $iv,
        string &$tag
    ): string {
        if (self::tagRequired($cipher)) {
            return \openssl_encrypt($data, $cipher, $key, 1, $iv, $tag, '', 16);
        } else {
            return \openssl_encrypt($data, $cipher, $key, 1, $iv);
        }
    }

    /**
     * OpenSSL decrypt wrapper function.
     *
     * @param string $input  Data to decrypt
     * @param string $cipher Cipher method to use
     * @param string $key    Key string
     * @param string $iv     Initialization vector
     * @param string $tag    AAD authentication tag
     *
     * @return string
     */
    protected static function opensslDecrypt(
        string $input,
        string $cipher,
        string $key,
        string $iv,
        string $tag
    ): string {
        if (self::tagRequired($cipher)) {
            return \openssl_decrypt($input, $cipher, $key, 1, $iv, $tag, '');
        } else {
            return \openssl_decrypt($input, $cipher, $key, 1, $iv);
        }
    }

    /**
     * Get IV size for specified CIPHER.
     *
     * @param string $cipher Openssl cipher
     *
     * @return int
     */
    protected static function ivSize(string $cipher): int
    {
        $ret = \openssl_cipher_iv_length($cipher);

        return $ret;
    }

    /**
     * Get a correctly sized IV for the specified cipher.
     *
     * @param string $cipher Openssl cipher
     *
     * @throws \Exception
     *
     * @return string
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
     * Determines if the provided cipher requires a tag.
     *
     * @param string $cipher Openssl cipher
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
