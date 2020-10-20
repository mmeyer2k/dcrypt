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
     * @param string     $data Data string to encrypt
     * @param OpensslKey $key Key object
     * @param string     $tag AAD tag
     *
     * @return string
     */
    protected static function opensslEncrypt(
        string $data,
        OpensslKey $key,
        string &$tag
    ): string
    {
        if (self::tagRequired($key->algo())) {
            return \openssl_encrypt(
                $data,
                $key->algo(),
                $key->encryptionKey(),
                1,
                $key->iv(),
                $tag,
                '',
                16
            );
        }

        return \openssl_encrypt($data, $key->algo(), $key->encryptionKey(), 1, $key->iv());
    }

    /**
     * OpenSSL decrypt wrapper function.
     *
     * @param string     $input Data string to decrypt
     * @param OpensslKey $key Key string
     * @param string     $tag AAD authentication tag
     *
     * @return string
     */
    protected static function opensslDecrypt(
        string $input,
        OpensslKey $key,
        string $tag
    ): string
    {
        if (self::tagRequired($key->algo())) {
            return \openssl_decrypt(
                $input,
                $key->algo(),
                $key->encryptionKey(),
                1,
                $key->iv(),
                $tag,
                ''
            );
        }

        return \openssl_decrypt($input, $key->algo(), $key->encryptionKey(), 1, $key->iv());
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
        return \openssl_cipher_iv_length($cipher);
    }

    /**
     * Get a correctly sized IV for the specified cipher.
     *
     * @param string $cipher Openssl cipher
     *
     * @return string
     * @throws \Exception
     *
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

        return strpos($cipher, '-gcm') || strpos($cipher, '-ccm');
    }
}
