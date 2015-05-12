<?php

/**
 * Otp.php
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt;

/**
 * 
 * One Time Pad
 * 
 * A simple stream encryption class designed to provide moderate security and 
 * high performance with low memory usage. Uses simple XOR operations to encrypt 
 * data with a key. The Otp::crypt() function is safer to run on pseuro-random
 * input that needs to be obscured.
 * 
 * Details of OTP's operation:
 * - output is in binary format
 * - key length is 512 bits
 * - does NOT chain cypher blocks, instead uses a form of block counter feedback
 * - does NOT generate IVs
 * - as with all stream ciphers, never use the same key more than once
 *   and never assume the authenticity of a message when decrypting
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     http://en.wikipedia.org/wiki/Stream_cipher
 */
class Otp
{

    /**
     * Encrypt or decrypt a binary input string.
     * 
     * @param string $input Input data to encrypt
     * @param string $key   Encryption/decryption key to use on input.
     * 
     * @return string
     */
    public static function crypt($input, $key)
    {
        $chunks = str_split($input, 64);

        foreach ($chunks as $i => &$chunk) {
            $chunk = $chunk ^ hash('sha512', $key . $i, true);
        }

        return implode($chunks);
    }

}
