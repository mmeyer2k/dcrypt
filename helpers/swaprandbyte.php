<?php

if (!function_exists('swaprandbyte')) {

    /**
     * Change a random byte, randomly. This function is used in unit testing
     * only and never in the namespaced areas of code.
     * 
     * @param string $input
     * @return string
     */
    function swaprandbyte($input)
    {
        $len = strlen($input);
        $input = str_split($input);
        $offset = rand(0, $len - 1);
        $byte = $input[$offset];
        $rbyte = \Dcrypt\Random::get(1);
        if ($byte === $rbyte) {
            $rbyte = (ord($rbyte) + 1) % 256;
            $rbyte = chr($rbyte);
        }
        $input[$offset] = $rbyte;
        
        return implode($input);
    }

}
