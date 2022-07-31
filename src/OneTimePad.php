<?php

declare(strict_types=1);

namespace Dcrypt;

class OneTimePad
{
    /**
     * Encrypt or decrypt a binary input string.
     *
     * @param string $input Input data to encrypt
     * @param string $key   Encryption/decryption key to use on input
     * @param string $algo  Hashing algo to generate keystream
     *
     * @throws Exceptions\InvalidKeyEncodingException
     * @throws Exceptions\InvalidKeyLengthException
     *
     * @return string
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
