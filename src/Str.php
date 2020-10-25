<?php

declare(strict_types=1);

/**
 * Str.php.
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

use Exception;

/**
 * Provides time-safe string comparison facilities, and safe string operations
 * on systems that have mb_* function overloading enabled.
 *
 * The functions in this class were inspired by the symfony's StringUtils class.
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 * @link     https://github.com/symfony/Security/blob/master/Core/Util/StringUtils.php
 * @link     https://php.net/manual/en/mbstring.overload.php
 */
final class Str
{
    /**
     * Compares two strings in constant time. Strings are hashed before
     * comparison so information is not leaked when strings are not of
     * equal length.
     *
     * @param string $known The string of known length to compare against
     * @param string $given The string that the user can control
     *
     * @return bool
     * @throws Exception
     */
    public static function equal(string $known, string $given): bool
    {
        // Create some entropy
        $nonce = random_bytes(16);

        // Prehash the input strings with the nonce
        $known = hash_hmac('sha256', $known, $nonce, true);
        $given = hash_hmac('sha256', $given, $nonce, true);

        return hash_equals($known, $given);
    }

    /**
     * Determine the length of the output of a given hash algorithm in bytes.
     *
     * @param string $algo Name of algorithm to look up
     *
     * @return int
     */
    public static function hashSize(string $algo): int
    {
        return self::strlen(hash($algo, 'hash me', true));
    }

    /**
     * Returns the number of bytes in a string.
     *
     * @param string $string The string whose length we wish to obtain
     *
     * @return int
     */
    public static function strlen(string $string): int
    {
        return mb_strlen($string, '8bit');
    }

    /**
     * Returns part of a string.
     *
     * @param string   $string The string whose length we wish to obtain
     * @param int      $start  Offset to start gathering output
     * @param int|null $length Distance from starting offset to gather
     *
     * @return string
     */
    public static function substr(string $string, int $start, int $length = null): string
    {
        return mb_substr($string, $start, $length, '8bit');
    }

    /**
     * Shifts bytes off of the front of a string and return. Input string is modified.
     *
     * @param string $input
     * @param int $bytes
     * @return string
     */
    public static function shift(string &$input, int $bytes): string
    {
        $shift = self::substr($input, 0, $bytes);

        $input = self::substr($input, $bytes);

        return $shift;
    }
}
