<?php

declare(strict_types=1);

/**
 * OneTimePad.php.
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

/**
 * A one time pad stream encryption class.
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     http://en.wikipedia.org/wiki/Stream_cipher
 */
class OneTimePad
{
    /**
     * Encrypt or decrypt a binary input string.
     *
     * @param string $input Input data to encrypt
     * @param string $key   Encryption/decryption key to use on input
     * @param string $algo  Hashing algo to generate keystream
     *
     * @return string
     * @throws Exceptions\InvalidKeyEncodingException
     * @throws Exceptions\InvalidKeyLengthException
     */
    public static function crypt(
        string $input,
        string $key,
        string $algo = 'sha3-512'
    ): string {
        // Split the input into chunks sized the same as the hash size
        $chunks = str_split($input, Str::hashSize($algo));

        // Determine total input length
        $length = Str::strlen($input);

        // Create a new key object
        $key = new OpensslKey($key, $algo);

        foreach ($chunks as $i => &$chunk) {
            // Create the info key based on counter
            $info = $length . $i;

            // Xor the derived key with the data chunk
            $chunk = $chunk ^ $key->deriveKey($info);
        }

        return implode($chunks);
    }
}
