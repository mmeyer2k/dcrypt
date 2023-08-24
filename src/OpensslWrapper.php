<?php

declare(strict_types=1);

namespace Dcrypt;

use Dcrypt\Exceptions\InternalOperationException;
use Exception;

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
     * @throws InternalOperationException
     */
    protected static function opensslEncrypt(string $data, OpensslKey $key, string &$tag): string
    {
        list($iv, $enc, $cipher, $options) = $key->wrapperVariables();

        try {
            if (self::tagLength($cipher) > 0) {
                $ciphertext = openssl_encrypt($data, $cipher, $enc, $options, $iv, $tag, '', 16);
            } else {
                $ciphertext = openssl_encrypt($data, $cipher, $enc, $options, $iv);
            }
        } catch (Exception $e) {
            throw new InternalOperationException($e->getMessage());
        }

        if ($ciphertext === false) {
            throw new InternalOperationException();
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
     * @throws InternalOperationException
     */
    protected static function opensslDecrypt(string $input, OpensslKey $key, string $tag): string
    {
        list($iv, $enc, $cipher, $options) = $key->wrapperVariables();

        try {
            if (self::tagLength($cipher) > 0) {
                $plaintext = openssl_decrypt($input, $cipher, $enc, $options, $iv, $tag, '');
            } else {
                $plaintext = openssl_decrypt($input, $cipher, $enc, $options, $iv);
            }
        } catch (Exception $e) {
            throw new InternalOperationException($e->getMessage());
        }

        if ($plaintext === false) {
            throw new InternalOperationException();
        }

        return $plaintext;
    }

    /**
     * Get IV size for specified CIPHER.
     *
     * @param string $cipher Openssl cipher
     *
     * @return int
     * @throws InternalOperationException
     */
    protected static function ivSize(string $cipher): int
    {
        try {
            $size = openssl_cipher_iv_length($cipher);
        } catch (Exception $e) {
            throw new InternalOperationException($e->getMessage());
        }

        if ($size === false) {
            throw new InternalOperationException();
        }

        return $size;
    }

    /**
     * Get a correctly sized IV for the specified cipher.
     *
     * @param string $cipher Openssl cipher
     *
     * @return string
     * @throws InternalOperationException
     */
    protected static function ivGenerate(string $cipher): string
    {
        $size = self::ivSize($cipher);

        if ($size === 0) {
            return '';
        }

        try {
            return random_bytes($size);
        } catch (Exception $e) {
            throw new InternalOperationException($e->getMessage());
        }
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
