<?php

namespace Dcrypt;

class Support
{

    /**
     * 
     * @param type $dec
     * @return type
     */
    protected static function _dec2bin($dec)
    {
        return hex2bin(str_pad(dechex($dec), 8, '0', STR_PAD_LEFT));
    }

    /**
     * 
     * @param type $bin
     * @return type
     */
    protected static function _bin2dec($bin)
    {
        return hexdec(bin2hex($bin));
    }

    /**
     * 
     * @param type $hexstr
     * @return type
     */
    protected static function hex2bin($hexstr)
    {
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
