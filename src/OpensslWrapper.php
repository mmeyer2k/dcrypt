<?php

declare(strict_types=1);

namespace Dcrypt;

use Dcrypt\Exceptions\InvalidInitializationVectorLength;
use Exception;

class OpensslWrapper
{
    /**
     * OpenSSL encrypt wrapper function.
     *
     * @param string $data Data to decrypt
     * @param OpensslKey $key Key string
     * @param string $tag AAD tag
     *
     * @return string
     */
    protected static function opensslEncrypt(string $data, OpensslKey $key, string &$tag): string
    {
        list($iv, $enc, $cipher) = $key->wrapperVariables();

        if (self::tagLength($cipher) > 0) {
            return openssl_encrypt($data, $cipher, $enc, 1, $iv, $tag, '', 16);
        }

        return openssl_encrypt($data, $cipher, $enc, 1, $iv);
    }

    /**
     * OpenSSL decrypt wrapper function.
     *
     * @param string $input Data to decrypt
     * @param OpensslKey $key Key string
     * @param string $tag AAD authentication tag
     *
     * @return string
     */
    protected static function opensslDecrypt(string $input, OpensslKey $key, string $tag): string
    {
        list($iv, $enc, $cipher) = $key->wrapperVariables();

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
     * @param string $cipher Openssl cipher name
     * @param string|null $ivr Optional IV, must be longer than min length required by cipher
     * @return string
     * @throws Exception
     */
    protected static function ivGenerate(string $cipher, ?string $ivr = null): string
    {
        $size = self::ivSize($cipher);

        if ($size === 0) {
            return '';
        }

        if ($ivr === null) {
            $ivr = random_bytes($size);
        }

        if (strlen($ivr) < $size) {
            throw new InvalidInitializationVectorLength;
        }

        return substr($ivr, 0, $size);
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
