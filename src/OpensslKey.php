<?php

declare(strict_types=1);

namespace Dcrypt;

use Dcrypt\Exceptions\InternalOperationException;
use Dcrypt\Exceptions\InvalidKeyEncodingException;
use Dcrypt\Exceptions\InvalidKeyLengthException;
use Exception;
use ValueError;

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
     * @throws InternalOperationException
     */
    public function authenticationKey(): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $this->_cipher);
    }

    /**
     * Generate the encryption key.
     *
     * @return string
     * @throws InternalOperationException
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
     * @throws InternalOperationException
     */
    public function deriveKey(string $info): string
    {
        try {
            $key = hash_hkdf($this->_algo, $this->_key, 0, $info, $this->_iv);
        } catch(Exception|ValueError $e) {
            throw new InternalOperationException($e->getMessage());
        }

        // Handle exceptions in versions prior to php 8.0
        // https://www.php.net/manual/en/function.hash-hkdf.php#refsect1-function.hash-hkdf-changelog
        if ($key === false) {
            throw new InternalOperationException();
        }

        return $key;
    }

    /**
     * Calculates a given message HMAC.
     *
     * @param string $message Message string to be hashed and signed
     *
     * @return string
     * @throws InternalOperationException
     */
    public function messageChecksum(string $message): string
    {
        try {
            $hmac = hash_hmac($this->_algo, $message, $this->authenticationKey(), true);
        } catch(ValueError $e) {
            throw new InternalOperationException($e->getMessage());
        }

        // Handle exceptions in versions prior to php 8.0
        // https://www.php.net/manual/en/function.hash-hmac.php#refsect1-function.hash-hmac-changelog
        if ($hmac === false) {
            throw new InternalOperationException();
        }

        return $hmac;
    }

    /**
     * Allows read only access to the internal variables needed by the openssl wrapper.
     *
     * @return array
     * @throws InternalOperationException
     */
    public function wrapperVariables(): array
    {
        return [
            $this->_iv,
            $this->encryptionKey(),
            $this->_cipher,
            OPENSSL_RAW_DATA,
        ];
    }

    /**
     * Generate a new key.
     *
     * @param int $bytes Size of key in bytes
     *
     * @return string
     * @throws InvalidKeyLengthException
     * @throws InternalOperationException
     */
    public static function create(int $bytes = 32): string
    {
        if ($bytes < 32) {
            throw new InvalidKeyLengthException();
        }

        try {
            $entropy = random_bytes($bytes);
        } catch (Exception $e) {
            throw new InternalOperationException($e->getMessage());
        }

        return base64_encode($entropy);
    }
}
