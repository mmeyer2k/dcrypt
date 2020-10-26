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
     * @var string
     */
    private $_iv;

    /**
     * @var false|string
     */
    private $_key;

    /**
     * @var string
     */
    private $_algo;

    /**
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
        string $cipher,
        string $iv
    ) {
        // Store args into the object
        [$this->_key, $this->_algo, $this->_cipher, $this->_iv] = func_get_args();

        // Attempt to base64 decode the key
        $this->_key = base64_decode($this->_key, true);

        // If key was not proper base64, bail out
        if ($this->_key === false) {
            throw new InvalidKeyEncodingException();
        }

        // If key was to short, bail out
        if (Str::length($this->_key) < 32) {
            throw new InvalidKeyLengthException();
        }
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
