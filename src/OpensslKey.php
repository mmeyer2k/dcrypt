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

use Dcrypt\Exceptions\InvalidKeyException;

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
    private $_ivr;

    /**
     * OpensslKey constructor.
     *
     * @param string $algo Algo to use for HKDF
     * @param string $key Key to use for encryption
     * @param string $ivr Initialization vector
     *
     * @throws InvalidKeyException
     */
    public function __construct(
        string $algo,
        string $key,
        string $ivr = ''
    )
    {
        // Store the key as what was supplied
        $this->_key = \base64_decode($key, true);

        // If key was not proper base64, bail out
        if ($this->_key === false) {
            throw new InvalidKeyException(InvalidKeyException::BASE64ENC);
        }

        // If key was to short, bail out
        if (Str::strlen($this->_key) < 32) {
            throw new InvalidKeyException(InvalidKeyException::KEYLENGTH);
        }

        // Store algo in object
        $this->_algo = $algo;

        // Store init vector in object
        $this->_ivr = $ivr;
    }

    /**
     * Generate the authentication key.
     *
     * @return string
     */
    public function authenticationKey(): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $this->_algo);
    }

    /**
     * Generate the encryption key.
     *
     * @return string
     */
    public function encryptionKey(): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $this->_algo);
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
        return \hash_hkdf($this->_algo, $this->_key, 0, $info, $this->_ivr);
    }

    /**
     * Calculates a given message HMAC.
     *
     * @param string $message
     * @return string
     */
    public function messageChecksum(string $message): string
    {
        return \hash_hmac($this->_algo, $message, $this->authenticationKey(), true);
    }

    /**
     * Returns the iv that object was created with.
     *
     * @return string
     */
    public function iv(): string
    {
        return $this->_ivr;
    }

    /**
     * Returns the cipher algo that object was created with.
     *
     * @return string
     */
    public function algo(): string
    {
        return $this->_algo;
    }

    /**
     * Generate a new key that meets requirements for dcrypt.
     *
     * @param int $bytes Size of key in bytes
     *
     * @return string
     * @throws InvalidKeyException
     */
    public static function create(int $bytes = 32): string
    {
        if ($bytes < 32) {
            throw new InvalidKeyException(InvalidKeyException::KEYLENGTH);
        }

        return \base64_encode(\random_bytes($bytes));
    }
}
