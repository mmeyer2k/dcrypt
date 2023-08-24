<?php

declare(strict_types=1);

namespace Dcrypt;

use Dcrypt\Exceptions\OpensslOperationException;

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
     * @throws OpensslOperationException
     */
    protected static function opensslEncrypt(string $data, OpensslKey $key, string &$tag): string
    {
        list($iv, $enc, $cipher) = $key->wrapperVariables();

        $options = OPENSSL_RAW_DATA;

        if (self::tagLength($cipher) > 0) {
            $ciphertext = openssl_encrypt($data, $cipher, $enc, $options, $iv, $tag, '', 16);
        } else {
            $ciphertext = openssl_encrypt($data, $cipher, $enc, $options, $iv);
        }

        if ($ciphertext === false) {
            throw new OpensslOperationException();
        }

        return $ciphertext;
    }

    /**
     * OpenSSL decrypt wrapper function.
     *
     * @param string     $input Data to decrypt
     * @param OpensslKey $key   Key string
     * @param string     $tag   AAD authentication tag
     *
     * @return string
     * @throws OpensslOperationException
     */
    protected static function opensslDecrypt(string $input, OpensslKey $key, string $tag): string
    {
        list($iv, $enc, $cipher) = $key->wrapperVariables();

        $options = OPENSSL_RAW_DATA;

        if (self::tagLength($cipher) > 0) {
            $plaintext = openssl_decrypt($input, $cipher, $enc, $options, $iv, $tag, '');
        } else {
            $plaintext = openssl_decrypt($input, $cipher, $enc, $options, $iv);
        }

        if ($plaintext === false) {
            throw new OpensslOperationException();
        }

        return $plaintext;
    }

    /**
     * Get IV size for specified CIPHER.
     *
     * @param string $cipher Openssl cipher
     *
     * @return int
     * @throws OpensslOperationException
     */
    protected static function ivSize(string $cipher): int
    {
        $size = openssl_cipher_iv_length($cipher);

        if ($size === false) {
            throw new OpensslOperationException();
        }

        return $size;
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
