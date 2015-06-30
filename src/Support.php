<?php

namespace Dcrypt;

class Support
{

    /**
     * Turns an integer into a 4 byte binary representation
     * 
     * @param int $dec Integer to convert to binary
     * 
     * @return string
     */
    protected static function dec2bin($dec)
    {
        return self::hex2bin(str_pad(dechex($dec), 8, '0', STR_PAD_LEFT));
    }

    /**
     * Reverses dec2bin
     * 
     * @param string $bin
     * 
     * @return type
     */
    protected static function bin2dec($bin)
    {
        return hexdec(bin2hex($bin));
    }

    /**
     * An internal hex2bin implementation for PHP 5.3
     * 
     * @param string $hexstr
     * 
     * @return string
     */
    protected static function hex2bin($hexstr)
    {
        if (function_exists('hex2bin')) {
            return hex2bin($hexstr);
        }
        
        $n = strlen($hexstr);
        $sbin = '';
        $i = 0;
        while ($i < $n) {
            $a = substr($hexstr, $i, 2);
            $c = pack('H*', $a);
            if ($i == 0) {
                $sbin = $c;
            } else {
                $sbin.= $c;
            }
            $i+=2;
        }
        
        return $sbin;
    }

}
