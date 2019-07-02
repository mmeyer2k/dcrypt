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
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $algo;

    /**
     * @var string
     */
    private $ivr;

    /**
     * OpensslKey constructor.
     *
     * @param string $algo Algo to use for HKDF
     * @param string $key  Key
     * @param string $ivr  Initialization vector
     * @throws InvalidKeyException
     */
    public function __construct(string $algo, string $key, string $ivr)
    {
        // Store the key as what was supplied
        $this->key = \base64_decode($key);

        // Make sure key was properly decoded and meets minimum required length
        if (!is_string($this->key) || Str::strlen($this->key) < 2048) {
            throw new InvalidKeyException("Key must be at least 2048 bytes and base64 encoded.");
        }

        // Make sure key meets minimum entropy requirement
        if (\count(\array_unique(\str_split($this->key))) < 250) {
            throw new InvalidKeyException("Key does not contain the minimum amount of entropy.");
        }

        // Store algo in object
        $this->algo = $algo;

        // Store init vector in object
        $this->ivr = $ivr;
    }

    /**
     * Generate the authentication key
     *
     * @param string $info
     * @return string
     */
    public function authenticationKey(string $info): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $info);
    }

    /**
     * Generate the encryption key
     *
     * @param string $info
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
     * @return string
     */
    public function deriveKey(string $info): string
    {
        return \hash_hkdf($this->algo, $this->key, 0, $info, $this->ivr);
    }

    /**
     * Generate a new key that meets requirements for dcrypt
     *
     * @param int $size Size of key in bytes
     * @return string
     * @throws InvalidKeyException
     */
    public static function create(int $bytes = 2048): string
    {
        if ($bytes < 2048) {
            throw new InvalidKeyException('Keys must be at least 2048 bytes long.');
        }

        return \base64_encode(\random_bytes($bytes));
    }
}