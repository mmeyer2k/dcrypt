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
     * @param string     $data Data to decrypt
     * @param OpensslKey $key  Key string
     * @param string     $tag  AAD tag
     *
     * @return string
     */
    protected static function opensslEncrypt(string $data, OpensslKey $key, string &$tag): string
    {
        list($iv, $enc, $cipher) = [$key->_iv, $key->encryptionKey(), $key->_cipher];

        if (self::tagLength($cipher) > 0) {
            return openssl_encrypt($data, $cipher, $enc, 1, $iv, $tag, '', 16);
        }

        return openssl_encrypt($data, $cipher, $enc, 1, $iv);
    }

    /**
     * OpenSSL decrypt wrapper function.
     *
     * @param string     $input Data to decrypt
     * @param OpensslKey $key   Key string
     * @param string     $tag   AAD authentication tag
     *
     * @return string
     */
    protected static function opensslDecrypt(string $input, OpensslKey $key, string $tag): string
    {
        list($iv, $enc, $cipher) = [$key->_iv, $key->encryptionKey(), $key->_cipher];

        if (self::tagLength($cipher) > 0) {
            return openssl_decrypt($input, $cipher, $enc, 1, $iv, $tag, '');
        }

        return openssl_decrypt($input, $cipher, $enc, 1, $iv);
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
        return openssl_cipher_iv_length($cipher);
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

        return random_bytes($size);
    }

    /**
     * Determines if the provided cipher requires a tag.
     *
     * @param string $cipher Openssl cipher
     *
     * @return int
     */
    protected static function tagLength(string $cipher): int
    {
        return stripos($cipher, '-gcm') || stripos($cipher, '-ccm') ? 16 : 0;
    }
}
