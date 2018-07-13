<?php

/**
 * Pkcs7.php
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
 * Provides PKCS #7 padding functionality.
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html
 */
class Pkcs7
{
    /**
     * PKCS #7 padding function.
     * 
     * @param string  $input     String to pad
     * @param int     $blocksize Block size in bytes
     * @return string
     */
    public static function pad(string $input, int $blocksize): string
    {
        // Determine the padding string that needs to be appended.
        $pad = self::paddingString(Str::strlen($input), $blocksize);

        // Return input + padding
        return $input . $pad;
    }

    /**
     * Create the padding string that will be appended to the input.
     * 
     * @param int $inputsize Size of the input in bytes
     * @param int $blocksize Blocksize in bytes
     * @return string
     */
    private static function paddingString(int $inputsize, int $blocksize): string
    {
        // Determine the amount of padding to use
        $pad = $blocksize - ($inputsize % $blocksize);

        // Create and return the padding string
        return \str_repeat(\chr($pad), $pad);
    }

    /**
     * PKCS #7 unpadding function.
     * 
     * @param string $input Padded string to unpad
     * @return string
     */
    public static function unpad(string $input): string
    {
        // Determine the padding size by converting the final byte of the  
        // input to its decimal value
        $padsize = \ord(Str::substr($input, -1));

        // Return string minus the padding amount
        return Str::substr($input, 0, Str::strlen($input) - $padsize);
    }
}
