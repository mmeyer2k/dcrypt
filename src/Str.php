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
 * The functions in this class are was based on the symfony security package. 
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
     * @param string $knownString The string of known length to compare against
     * @param string $userInput   The string that the user can control
     *
     * @return bool true if the two strings are the same, false otherwise
     */
    public static function equals($knownString, $userInput)
    {
        // Avoid making unnecessary duplications of secret data
        if (!is_string($knownString)) {
            $knownString = (string) $knownString;
        }

        if (!is_string($userInput)) {
            $userInput = (string) $userInput;
        }

        if (function_exists('hash_equals')) {
            return hash_equals($knownString, $userInput);
        }

        $knownLen = self::strlen($knownString);
        $userLen = self::strlen($userInput);

        if ($userLen !== $knownLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $knownLen; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userInput[$i]));
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
    public static function strlen($string)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($string, '8bit');
        }

        return strlen($string);
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
    public static function substr($string, $start, $length = null)
    {
        if (function_exists('mb_substr')) {

            // Fix a weird quirk in PHP versions prior to 5.4.8
            if ($length === null && version_compare('5.4.8', PHP_VERSION)) {
                $length = self::strlen($string);
            }

            return mb_substr($string, $start, $length, '8bit');
        }

        return substr($string, $start, $length);
    }

}
