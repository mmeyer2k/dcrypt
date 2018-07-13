<?php

/**
 * Otp.php
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
 * A one time pad stream encryption class.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     http://en.wikipedia.org/wiki/Stream_cipher
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Otp
{
    /**
     * Encrypt or decrypt a binary input string.
     * 
     * @param string $input    Input data to encrypt
     * @param string $password Encryption/decryption key to use on input
     * @param string $algo     Hashing algo to generate keystream
     * @return string
     */
    public static function crypt(string $input, string $password, string $algo = 'sha512'): string
    {
        $chunks = \str_split($input, Str::hashSize($algo));

        $length = Str::strlen($input);
        
        foreach ($chunks as $i => &$chunk) {
            $chunk = $chunk ^ \hash_hmac($algo, $password . $length, $i, true);
        }

        return \implode($chunks);
    }
}
