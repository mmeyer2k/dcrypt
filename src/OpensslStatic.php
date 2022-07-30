<?php

declare(strict_types=1);

namespace Dcrypt;

use Dcrypt\Exceptions\InvalidChecksumException;
use Exception;

final class OpensslStatic extends OpensslWrapper
{
    /**
     * Decrypt raw data string.
     *
     * @param string $data Data to be decrypted
     * @param string $key Key material
     * @param string $cipher OpenSSL cipher name
     * @param string $algo Hash algo name
     * @return string
     * @throws Exceptions\InvalidKeyEncodingException
     * @throws Exceptions\InvalidKeyLengthException
     * @throws InvalidChecksumException
     */
    public static function decrypt(
        string $data,
        string $key,
        string $cipher,
        string $algo,
    ): string {
        // Shift the IV off of the beginning of the ciphertext
        $ivr = Str::shift($data, parent::ivSize($cipher));

        // Shift off the checksum
        $sum = Str::shift($data, Str::hashSize($algo));

        // Shift off the AAD tag (if present)
        $tag = Str::shift($data, parent::tagLength($cipher));

        // Create a new key object
        $key = new OpensslKey($key, $algo, $cipher, $ivr);

        // Calculate checksum of message payload for verification
        $chk = $key->messageChecksum($data);

        // Compare given checksum against computed checksum
        if (!Str::equal($chk, $sum)) {
            throw new InvalidChecksumException();
        }

        // Decrypt message and return
        return parent::opensslDecrypt($data, $key, $tag);
    }

    /**
     * Encrypt raw string.
     *
     * @param string $data Data to be encrypted
     * @param string $key Key material
     * @param string $cipher OpenSSL cipher name
     * @param string $algo Hash algo name
     * @param string|null $ivr Initialization vector or null to generate one
     * @return string
     * @throws Exceptions\InvalidKeyEncodingException
     * @throws Exceptions\InvalidKeyLengthException
     * @throws Exception
     */
    public static function encrypt(
        string $data,
        string $key,
        string $cipher,
        string $algo,
        ?string $ivr = null,
    ): string {
        // Generate IV of appropriate size
        $ivr = parent::ivGenerate($cipher, $ivr);

        // Create key derivation object
        $key = new OpensslKey($key, $algo, $cipher, $ivr);

        // Create a variable for the authentication tag to be returned by reference
        $tag = '';

        // Encrypt the plaintext
        $msg = parent::opensslEncrypt($data, $key, $tag);

        // Generate the ciphertext checksum
        $chk = $key->messageChecksum($msg);

        // Return concatenation of iv + checksum + tag + ciphertext
        return $ivr . $chk . $tag . $msg;
    }
}
