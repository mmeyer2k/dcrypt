<?php

class TestSupport extends \PHPUnit\Framework\TestCase
{
    /**
     * Change a random byte, randomly. This function is used in unit testing
     * only and never in the namespaced areas of code.
     *
     * @param string $inp
     * @return string
     */
    public static function swaprandbyte($inp)
    {
        // @codeCoverageIgnoreStart
        $len = strlen($inp);
        $inp = str_split($inp);
        $off = rand(0, $len - 1);
        $byte = $inp[$off];
        $rbyte = \random_bytes(1);
        if ($byte === $rbyte) {
            $rbyte = (ord($rbyte) + 1) % 256;
            $rbyte = chr($rbyte);
        }
        $inp[$off] = $rbyte;
        // @codeCoverageIgnoreEnd
        return implode($inp);
    }
}
