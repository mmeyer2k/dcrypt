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
            $rbyte = ord($rbyte);
            if($rbyte === 0) {
                $rbyte = 255;
            } elseif($rbyte === 255) {
                $rbyte = 0;
            } else {
                $rbyte = $rbyte + 1;
            }
            $rbyte = chr($rbyte);
        }
        $input[$offset] = $rbyte;
        
        return implode($input);
    }

}
