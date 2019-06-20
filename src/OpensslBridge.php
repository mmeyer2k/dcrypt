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
     * Decrypt cyphertext
     *
     * @param string $data Cyphertext to decrypt
     * @param string $pass Password that should be used to decrypt input data
     * @return string
     */
    public static function decrypt(string $data, string $pass): string
    {
        return OpensslStatic::decrypt($data, $pass, static::CIPHER, static::ALGO, static::COST);
    }

    /**
     * Encrypt plaintext
     *
     * @param string $data Plaintext string to encrypt.
     * @param string $pass Password used to encrypt data.
     * @return string
     */
    public static function encrypt(string $data, string $pass): string
    {
        return OpensslStatic::encrypt($data, $pass, static::CIPHER, static::ALGO, static::COST);
    }
}
