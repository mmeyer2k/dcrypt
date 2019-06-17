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
     * @param string $pass
     * @param string $cipher
     * @param string $algo
     * @return string
     * @throws \Exception
     */
    public static function decrypt(string $data, string $pass, string $cipher, string $algo): string
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

        // Gather the iterations portion of the cipher text as packed/encrytped unsigned long
        $itr = Str::substr($data, $isz + $hsz + $tsz, 4);

        // Gather message portion of ciphertext after iv and checksum
        $msg = Str::substr($data, $isz + $hsz + $tsz + 4);

        // Calculate verification checksum
        $chk = \hash_hmac($algo, ($msg . $itr . $ivr), $pass, true);

        // Verify HMAC before decrypting
        if (!Str::equal($chk, $sum)) {
            throw new \InvalidArgumentException('Decryption can not proceed due to invalid cyphertext checksum.');
        }

        // Decrypt and unpack the cost parameter to match what was used during encryption
        $cost = \unpack('N', $itr ^ \hash_hmac($algo, $ivr, $pass, true))[1];

        // Derive key from password using pbkdf2
        $key = \hash_pbkdf2($algo, ($pass . $cipher), $ivr, $cost, 0, true);

        // Decrypt message and return
        return parent::openssl_decrypt($msg, $cipher, $key, $ivr, $tag);
    }

    /**
     * Encrypt raw string
     *
     * @param string $data
     * @param string $pass
     * @param string $cipher
     * @param string $algo
     * @param int $cost
     * @return string
     * @throws \Exception
     */
    public static function encrypt(string $data, string $pass, string $cipher, string $algo, int $cost = 1): string
    {
        // Generate IV of appropriate size.
        $ivr = \random_bytes(parent::ivSize($cipher));

        // Derive key from password with hash_pbkdf2 function.
        // Append CIPHER to password beforehand so that cross-method decryptions will fail at checksum step
        $key = \hash_pbkdf2($algo, ($pass . $cipher), $ivr, $cost, 0, true);

        // Create a placeholder for the authentication tag to be passed by reference
        $tag = '';

        // Encrypt the plaintext data
        $msg = parent::openssl_encrypt($data, $cipher, $key, $ivr, $tag);

        // Convert cost integer into 4 byte string and XOR it with a newly derived key
        $itr = \pack('N', $cost) ^ \hash_hmac($algo, $ivr, $pass, true);

        // Generate the ciphertext checksum to prevent bit tampering
        $chk = \hash_hmac($algo, ($msg . $itr . $ivr), $pass, true);

        // Return iv + checksum + tag + iterations + cyphertext
        return $ivr . $chk . $tag . $itr . $msg;
    }
}
