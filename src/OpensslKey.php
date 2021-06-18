<?php

declare(strict_types=1);

/**
 * OpensslKey.php.
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

use Dcrypt\Exceptions\InvalidKeyEncodingException;
use Dcrypt\Exceptions\InvalidKeyLengthException;
use Exception;

/**
 * Provides key derivation functions.
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 */
final class OpensslKey
{
    /**
     * High entropy key.
     *
     * @var string
     */
    private $_key;

    /**
     * Algo string.
     *
     * @var string
     */
    private $_algo;

    /**
     * High entropy salt.
     *
     * @var string
     */
    private $_iv;

    /**
     * Name of cipher.
     *
     * @var string
     */
    private $_cipher;

    /**
     * OpensslKey constructor.
     *
     * @param string $key    Key to use for encryption
     * @param string $algo   Algo to use for HKDF
     * @param string $cipher Name of cipher
     * @param string $iv     Initialization vector
     *
     * @throws InvalidKeyLengthException
     * @throws InvalidKeyEncodingException
     */
    public function __construct(
        string $key,
        string $algo,
        string $cipher = '',
        string $iv = ''
    ) {
        // Store the key as what was supplied
        $this->_key = self::decode($key);

        // If key was not proper base64, bail out
        if ($this->_key === false) {
            throw new InvalidKeyEncodingException();
        }

        // If key was too short, bail out
        if (Str::strlen($this->_key) < 32) {
            throw new InvalidKeyLengthException();
        }

        // Store algo in object
        $this->_algo = $algo;

        // Store init vector in object
        $this->_iv = $iv;

        // Store the cipher name
        $this->_cipher = $cipher;
    }

    /**
     * Decode key and test validity.
     * 
     * @param string $key Encoded key to unpack
     * 
     * @throws InvalidKeyLengthException
     * @throws InvalidKeyEncodingException
     * 
     * @return string
     */
    private static function decode(string $key): string
    {
        // Store the key as what was supplied
        $key = base64_decode($key, true);

        // If key was not proper base64, bail out
        if ($key === false) {
            throw new InvalidKeyEncodingException();
        }

        // If key was too short, bail out
        if (Str::strlen($key) < 32) {
            throw new InvalidKeyLengthException();
        }

        return $key;
    }

    /**
     * Generate the authentication key.
     *
     * @return string
     */
    public function authenticationKey(): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $this->_cipher);
    }

    /**
     * Generate the encryption key.
     *
     * @return string
     */
    public function encryptionKey(): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $this->_cipher);
    }

    /**
     * Derive a key with differing info string parameters.
     *
     * @param string $info Info parameter to provide to hash_hkdf
     *
     * @return string
     */
    public function deriveKey(string $info): string
    {
        return hash_hkdf($this->_algo, $this->_key, 0, $info, $this->_iv);
    }

    /**
     * Calculates a given message HMAC.
     *
     * @param string $message
     *
     * @return string
     */
    public function messageChecksum(string $message): string
    {
        return hash_hmac($this->_algo, $message, $this->authenticationKey(), true);
    }

    /**
     * Allows read only access to the internal variables needed by the openssl wrapper.
     *
     * @return array
     */
    public function wrapperVariables(): array
    {
        return [
            $this->_iv,
            $this->encryptionKey(),
            $this->_cipher,
        ];
    }

    /**
     * Generate a new key.
     *
     * @param int $bytes Size of key in bytes
     *
     * @throws Exception
     * @throws InvalidKeyLengthException
     *
     * @return string
     */
    public static function create(int $bytes = 32): string
    {
        if ($bytes < 32) {
            throw new InvalidKeyLengthException();
        }

        return base64_encode(random_bytes($bytes));
    }
}
