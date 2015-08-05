<?php

/**
 * Str.php
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
 * Provides time-safe string comparison facilities, and safe string operations
 * on systems that have mb_* function overloading enabled.
 * 
 * The functions in this class were inspired by the symfony's StringUtils class. 
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://github.com/symfony/Security/blob/master/Core/Util/StringUtils.php
 * @link     https://php.net/manual/en/mbstring.overload.php
 */
class Str
{

    /**
     * Private constant-time strcmp method to use when hash_equals is unavailable.
     *
     * @param string $knownHash Hash of the known string
     * @param string $givenHash Hash of the given string
     *
     * @return bool true if the two strings are the same, false otherwise
     */
    private static function strcmp($knownHash, $givenHash)
    {
        $result = 0;

        // XOR the bytes of the 2 input hashes and loop over them.
        // Each byte value is then added to a running total...
        foreach (\str_split($knownHash ^ $givenHash) as $xbyte) {
            $result += \ord($xbyte);
        }

        // Strings are equal if the final result is exactly zero
        return 0 === $result;
    }

    /**
     * Compares two strings in constant time. Strings are hashed before 
     * comparison so information is not leaked when strings are not of
     * equal length.
     *
     * @param string $known       The string of known length to compare against
     * @param string $given       The string that the user can control
     * @param bool   $hash_equals Use hash_equals() if available
     *
     * @return bool
     */
    public static function equal($known, $given, $hash_equals = true)
    {
        // We hash the 2 inputs at this point because hash_equals is still 
        // vulnerable to timing attacks when the inputs have different sizes.
        // Inputs are also cast to string like in symfony stringutils.
        $nonce = Random::get(32);
        
        $known = \hash_hmac('sha256', (string) $known, $nonce, true);
        $given = \hash_hmac('sha256', (string) $given, $nonce, true);

        if ($hash_equals === true && \function_exists('hash_equals')) {
            return \hash_equals($known, $given); // @codeCoverageIgnore
        }

        return self::strcmp($known, $given);
    }

    /**
     * Returns the number of bytes in a string.
     *
     * @param string $string The string whose length we wish to obtain
     *
     * @return int
     */
    protected static function strlen($string)
    {
        if (\function_exists('mb_strlen')) {
            return \mb_strlen($string, '8bit');
        }

        return \strlen($string); // @codeCoverageIgnore
    }

    /**
     * Returns part of a string.
     *
     * @param string $string The string whose length we wish to obtain
     * @param int    $start
     * @param int    $length
     * 
     * @return string the extracted part of string; or FALSE on failure, or an empty string.
     */
    protected static function substr($string, $start, $length = null)
    {
        if (\function_exists('mb_substr')) {

            // Fix a weird quirk in PHP versions prior to 5.4.8
            if ($length === null && \version_compare('5.4.8', PHP_VERSION)) {
                $length = self::strlen($string);
            }

            return \mb_substr($string, $start, $length, '8bit');
        }

        return \substr($string, $start, $length); // @codeCoverageIgnore
    }

}
