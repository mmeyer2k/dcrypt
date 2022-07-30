<?php

declare(strict_types=1);

namespace Dcrypt;

use Exception;

class OpensslBridge
{
    /**
     * Decrypt ciphertext.
     *
     * @param string $data Ciphertext to decrypt
     * @param string $key Key which will be used to decrypt data
     * @return string
     * @throws Exceptions\InvalidChecksumException
     * @throws Exceptions\InvalidKeyEncodingException
     * @throws Exceptions\InvalidKeyLengthException
     */
    public static function decrypt(string $data, string $key): string
    {
        return OpensslStatic::decrypt($data, $key, static::CIPHER, static::ALGO);
    }

    /**
     * Encrypt plaintext.
     *
     * @param string $data Plaintext string to encrypt.
     * @param string $key Key which will be used to encrypt data
     * @return string
     * @throws Exception
     */
    public static function encrypt(string $data, string $key): string
    {
        return OpensslStatic::encrypt($data, $key, static::CIPHER, static::ALGO);
    }
}
