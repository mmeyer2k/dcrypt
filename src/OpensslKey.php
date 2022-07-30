<?php

declare(strict_types=1);

namespace Dcrypt;

use Dcrypt\Exceptions\InvalidKeyEncodingException;
use Dcrypt\Exceptions\InvalidKeyLengthException;
use Exception;

final class OpensslKey
{
    /**
     * OpensslKey constructor.
     *
     * @param string $key Key to use for encryption
     * @param string $algo Algo to use for key derivation
     * @param string $cipher Name of cipher
     * @param string $iv Initialization vector
     * @throws InvalidKeyEncodingException
     * @throws InvalidKeyLengthException
     */
    public function __construct(
        private string $key,
        private string $algo,
        private string $cipher,
        private string $iv
    )
    {
        // Store the key as what was supplied
        $this->key = self::decode($key);
    }

    /**
     * Decode key and test validity.
     *
     * @param string $key Encoded key to unpack
     * @return string
     * @throws InvalidKeyEncodingException
     * @throws InvalidKeyLengthException
     */
    private static function decode(string $key): string
    {
        // Store the key as what was supplied
        $key = base64_decode($key, true);

        // If key was not proper base64, bail out
        if ($key === false) {
            throw new InvalidKeyEncodingException;
        }

        // If key was too short, bail out
        if (Str::strlen($key) < 32) {
            throw new InvalidKeyLengthException;
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
        return $this->deriveKey(__FUNCTION__ . '|' . $this->cipher);
    }

    /**
     * Generate the encryption key.
     *
     * @return string
     */
    public function encryptionKey(): string
    {
        return $this->deriveKey(__FUNCTION__ . '|' . $this->cipher);
    }

    /**
     * Derive a key with differing info string parameters.
     *
     * @param string $info Info parameter to provide to hash_hkdf
     * @return string
     */
    public function deriveKey(string $info): string
    {
        return hash_hkdf($this->algo, $this->key, 0, $info, $this->iv);
    }

    /**
     * Calculates a given message HMAC.
     *
     * @param string $message
     * @return string
     */
    public function messageChecksum(string $message): string
    {
        return hash_hmac($this->algo, $message, $this->authenticationKey(), true);
    }

    /**
     * Allows read only access to the internal variables needed by the openssl wrapper.
     *
     * @return array
     */
    public function wrapperVariables(): array
    {
        return [
            $this->iv,
            $this->encryptionKey(),
            $this->cipher,
        ];
    }

    /**
     * Generate a new key.
     *
     * @param int $bytes Size of key in bytes
     * @return string
     * @throws InvalidKeyLengthException
     * @throws Exception
     */
    public static function create(int $bytes = 32): string
    {
        if ($bytes < 32) {
            throw new InvalidKeyLengthException();
        }

        return base64_encode(random_bytes($bytes));
    }
}
