<?php declare(strict_types=1);

/**
 * OpensslBridge.php
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
 * Provides functionality common to the dcrypt AES block ciphers. Extend this class to customize your cipher suite.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class OpensslBridge
{
    /**
     * Decrypt ciphertext
     *
     * @param string $data Ciphertext to decrypt
     * @param string $key  Key which will be used to decrypt data
     *
     * @return string
     */
    public static function decrypt(string $data, string $key): string
    {
        return OpensslStatic::decrypt($data, $key, static::CIPHER, static::ALGO);
    }

    /**
     * Encrypt plaintext
     *
     * @param string $data Plaintext string to encrypt.
     * @param string $key  Key which will be used to encrypt data
     *
     * @return string
     */
    public static function encrypt(string $data, string $key): string
    {
        return OpensslStatic::encrypt($data, $key, static::CIPHER, static::ALGO);
    }
}
