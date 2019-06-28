<?php declare(strict_types=1);

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
 */
class Otp
{
    /**
     * Encrypt or decrypt a binary input string.
     * 
     * @param string $input   Input data to encrypt
     * @param string $passkey Encryption/decryption key to use on input
     * @param int    $cost    Cost value to harden password with, or 0 if using a key
     * @param string $algo    Hashing algo to generate keystream
     * @return string
     */
    public static function crypt(string $input, string $passkey, int $cost = 0, string $algo = 'sha512'): string
    {
        $chunks = \str_split($input, Str::hashSize($algo));

        $length = Str::strlen($input);

        $key = new OpensslKeyGenerator($algo, $passkey, 'otp', '', $cost);

        foreach ($chunks as $i => &$chunk) {
            $info = $length . $i . $cost;
            $chunk = $chunk ^ $key->deriveKey($info);
        }

        return \implode($chunks);
    }
}
