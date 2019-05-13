<?php declare(strict_types=1);

/**
 * Rot128.php
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

class Rot128
{
    /**
     * Rot-128 encode a binary string with strtr.
     *
     * @param string $input
     * @return string
     */
    public static function flip(string $input): string
    {
        $translation = [];

        foreach (\range(0, 255) as $r) {
            $translation[chr($r)] = chr($r + 128);
        }

        return strtr($input, $translation);
    }
}