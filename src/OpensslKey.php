<?php declare(strict_types=1);

/**
 * OpensslKey.php
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

use Dcrypt\Exceptions\InvalidKeyException;

/**
 * Provides key derivation functions
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
final class OpensslKey
{
    /**
     * High entropy key
     *
     * @var string
     */
    private $_key;

    /**
     * Algo string
     *
     * @var string
     */
    private $_algo;

    /**
     * High entropy salt
     *
     * @var string
     */
    private $_ivr;

    /**
     * OpensslKey constructor.
     *
     * @param string $algo    Algo to use for HKDF
     * @param string $key     Key
     * @param string $ivr     Initialization vector
     * @param bool   $testKey Validate the key
     *
     * @throws InvalidKeyException
     */
    public function __construct(
        string $algo,
        string $key,
        string $ivr = '',
        bool $testKey = true
    )
    {
        // Store the key as what was supplied
        $this->_key = \base64_decode($key);

        if ($testKey) {
            // Make sure key was properly decoded and meets minimum required length
            if (!is_string($this->_key) || Str::strlen($this->_key) < 2048) {
                throw new InvalidKeyException(InvalidKeyException::KEYLENGTH);
            }

            // Make sure key meets minimum entropy requirement
            if (self::testKeyEntropy($this->_key) === false) {
                throw new InvalidKeyException(InvalidKeyException::KEYRANDOM);
            }
        }

        // Store algo in object
        $this->_algo = $algo;

        // Store init vector in object
        $this->_ivr = $ivr;
    }

    /**
     * Generate the authentication key
     *
     * @param string $info The extra info parameter for hash_hkdf
     *
     * @return string
     */
    public function authenticationKey(string $info): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $info);
    }

    /**
     * Generate the encryption key
     *
     * @param string $info The extra info parameter for hash_hkdf
     *
     * @return string
     */
    public function encryptionKey(string $info): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $info);
    }

    /**
     * Derive a key with differing info string parameters
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
     * Generate a new key that meets requirements for dcrypt
     *
     * @param int $bytes Size of key in bytes
     *
     * @return string
     * @throws InvalidKeyException
     */
    public static function create(int $bytes = 2048): string
    {
        if ($bytes < 2048) {
            throw new InvalidKeyException(InvalidKeyException::KEYLENGTH);
        }

        return \base64_encode(\random_bytes($bytes));
    }

    /**
     * Returns true if key has enough entropy
     *
     * @param string $key Key string to test
     *
     * @return bool
     */
    private static function testKeyEntropy(string $key): bool
    {
        return \count(\array_unique(\str_split($key))) > 250;
    }
}