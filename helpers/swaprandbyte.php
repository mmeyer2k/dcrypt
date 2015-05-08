<?php

if (!function_exists('swaprandbyte')) {

    /**
     * Change a random byte, randomly.
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
            if(ord($rbyte) === 0) {
                $rbyte = 255;
            } elseif(ord($rbyte) === 255) {
                $rbyte = 0;
            } else {
                $rbyte = $rbyte + 1;
            }
        }
        $input[$offset] = $rbyte;
        
        return implode($input);
    }

}
