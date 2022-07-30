<?php

declare(strict_types=1);

namespace Dcrypt;

use Exception;

final class Str
{
    /**
     * @throws Exception
     */
    public static function equal(string $known, string $given): bool
    {
        // Create some entropy
        $nonce = random_bytes(16);

        // Pre-hash the input strings with the nonce
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
     * Shifts bytes off of the front of a string and return. Input string is modified by reference.
     *
     * @param string $input
     * @param int    $bytes
     *
     * @return string
     */
    public static function shift(string &$input, int $bytes): string
    {
        $shift = self::substr($input, 0, $bytes);

        $input = self::substr($input, $bytes);

        return $shift;
    }

    /**
     * Generates a cryptographically secure random token string of a specified length.
     *
     * @param int $length Length of random string to generate
     *
     * @throws \Exception
     *
     * @return string
     */
    public static function token(int $length): string
    {
        $length = max($length, 0);

        $bucket = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        $output = '';

        for ($x = 0; $x < $length; $x++) {
            $idx = random_int(0, 61);

            $output .= substr($bucket, $idx, 1);
        }

        return $output;
    }
}
