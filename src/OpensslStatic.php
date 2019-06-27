<?php declare(strict_types=1);

/**
 * OpensslStatic.php
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
 * Static functions that handle encryption/decryption with openssl.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
final class OpensslStatic extends OpensslWrapper
{
    /**
     * Decrypt raw data string
     *
     * @param string $data
     * @param string $passkey
     * @param string $cipher
     * @param string $algo
     * @return string
     * @throws \Exception
     */
    public static function decrypt(string $data, string $passkey, string $cipher, string $algo, int $cost = 0): string
    {
        // Calculate the hash checksum size in bytes for the specified algo
        $hsz = Str::hashSize($algo);

        // Find the tag size for this cipher mode. Unless using GCM/CCM this will be zero.
        $tsz = parent::tagRequired($cipher) ? 4 : 0;

        // Ask openssl for the IV size needed for specified cipher
        $isz = parent::ivSize($cipher);

        // Find the IV at the beginning of the cypher text
        $ivr = Str::substr($data, 0, $isz);

        // Gather the checksum portion of the ciphertext
        $sum = Str::substr($data, $isz, $hsz);

        // Gather the GCM/CCM authentication tag
        $tag = Str::substr($data, $isz + $hsz, $tsz);

        // Gather message portion of ciphertext after iv and checksum
        $msg = Str::substr($data, $isz + $hsz + $tsz);

        // Create password derivation object
        $key = new OpensslKeyGenerator($algo, $passkey, $cipher, $ivr, $cost);

        // Calculate verification checksum
        $chk = \hash_hmac($algo, $msg, $key->authenticationKey(), true);

        // Verify HMAC before decrypting
        if (!Str::equal($chk, $sum)) {
            throw new Exceptions\InvalidChecksum('Decryption can not proceed due to invalid cyphertext checksum.');
        }

        // Decrypt message and return
        return parent::openssl_decrypt($msg, $cipher, $key->encryptionKey(), $ivr, $tag);
    }

    /**
     * Encrypt raw string
     *
     * @param string $data
     * @param string $passkey
     * @param string $cipher
     * @param string $algo
     * @param int $cost
     * @return string
     * @throws \Exception
     */
    public static function encrypt(string $data, string $passkey, string $cipher, string $algo, int $cost = 0): string
    {
        // Generate IV of appropriate size.
        $ivr = parent::ivGenerate($cipher);

        // Create password derivation object
        $key = new OpensslKeyGenerator($algo, $passkey, $cipher, $ivr, $cost);

        // Create a placeholder for the authentication tag to be passed by reference
        $tag = '';

        // Encrypt the plaintext data
        $msg = parent::openssl_encrypt($data, $cipher, $key->encryptionKey(), $ivr, $tag);

        // Generate the ciphertext checksum to prevent bit tampering
        $chk = \hash_hmac($algo, $msg, $key->authenticationKey(), true);

        // Return iv + checksum + tag + cyphertext
        return $ivr . $chk . $tag . $msg;
    }
}
