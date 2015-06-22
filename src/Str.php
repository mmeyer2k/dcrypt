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
     * Compares two strings.
     *
     * This method implements a constant-time algorithm to compare strings.
     * Regardless of the used implementation, it will leak length information.
     *
     * @param string $known       The string of known length to compare against
     * @param string $given       The string that the user can control
     * @param bool   $hash_equals Use hash_equals() if available
     *
     * @return bool true if the two strings are the same, false otherwise
     */
    public static function equal($known, $given, $hash_equals = true)
    {
        $nonce = Random::get(32);
        
        $known = (string) $known;
        $given = (string) $given;
        
        $known = hash_hmac('sha256', $known, $nonce, true);
        $given = hash_hmac('sha256', $given, $nonce, true);

        if ($hash_equals === true && function_exists('hash_equals')) {
            return hash_equals($known, $given); // @codeCoverageIgnore
        }

        $result = 0;

        for ($i = 0; $i < 32; $i++) {
            $result |= ord($known[$i]) ^ ord($given[$i]);
        }

        // They are only identical strings if $result is exactly 0...
        return 0 === $result;
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
        if (function_exists('mb_strlen')) {
            return mb_strlen($string, '8bit');
        }

        return strlen($string); // @codeCoverageIgnore
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
        if (function_exists('mb_substr')) {

            // Fix a weird quirk in PHP versions prior to 5.4.8
            if ($length === null && version_compare('5.4.8', PHP_VERSION)) {
                $length = self::strlen($string);
            }

            return mb_substr($string, $start, $length, '8bit');
        }

        return substr($string, $start, $length); // @codeCoverageIgnore
    }

}
