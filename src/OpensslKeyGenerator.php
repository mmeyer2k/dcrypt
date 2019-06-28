<?php declare(strict_types=1);

/**
 * OpensslKeyGenerator.php
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
 * Provides key derivation functions
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
final class OpensslKeyGenerator
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
     * @var string
     */
    private $cipher;

    /**
     * OpensslKeyGenerator constructor.
     *
     * @param string $algo
     * @param string $passkey
     * @param string $cipher
     * @param string $ivr
     * @param int    $cost
     */
    public function __construct(string $algo, string $passkey, string $cipher, string $ivr, int $cost)
    {
        // When cost is 0 then we are in key mode
        if ($cost === 0) {
            // Make sure key meets minimum required length
            if (Str::strlen($passkey) < 256) {
                throw new Exceptions\InvalidKeyException("Key must be at least 2048 bits long.");
            }

            // Store the key as what was supplied
            $this->key = $passkey;
        } else {
            // Derive the key from the password and store in object
            $this->key = \hash_pbkdf2($algo, $passkey, $ivr, $cost, 0, true);
        }

        // Store the cipher string
        $this->cipher = $cipher;

        // Store algo in object
        $this->algo = $algo;

        // Store init vector in object
        $this->ivr = $ivr;
    }

    /**
     * Generate the authentication key
     *
     * @return string
     */
    public function authenticationKey(): string
    {
        return $this->deriveKey(__FUNCTION__);
    }

    /**
     * Generate the encryption key
     *
     * @return string
     */
    public function encryptionKey(): string
    {
        return $this->deriveKey(__FUNCTION__);
    }

    /**
     * Derive a key with differing authinfo strings
     *
     * @param string $info
     * @return string
     * @throws \Exception
     */
    public function deriveKey(string $info): string
    {
        $info = $info . '|' . $this->cipher;

        $key = \hash_hkdf($this->algo, $this->key, 0, $info, $this->ivr);

        if ($key === false) {
            throw new Exceptions\InvalidAlgoException("Hash algo $this->algo is not supported");
        }

        return $key;
    }
}