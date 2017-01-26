<?php

class TestSupport extends PHPUnit_Framework_TestCase
{
    public static function mcryptDeprecated() 
    {
        return version_compare(PHP_VERSION, '7.1.0') >= 0;
    }
    
    public static function mcryptCiphers()
    {
        return array(
            MCRYPT_3DES,
            MCRYPT_BLOWFISH,
            MCRYPT_BLOWFISH_COMPAT,
            MCRYPT_DES,
            MCRYPT_LOKI97,
            MCRYPT_CAST_128,
            MCRYPT_CAST_256,
            MCRYPT_RC2,
            MCRYPT_RIJNDAEL_128,
            MCRYPT_RIJNDAEL_192,
            MCRYPT_RIJNDAEL_256,
            MCRYPT_SAFERPLUS,
            MCRYPT_SERPENT,
            MCRYPT_TRIPLEDES,
            MCRYPT_TWOFISH,
            MCRYPT_XTEA,
        );
    }
    
    public static function mcryptModes()
    {
        return array(
            MCRYPT_MODE_CBC,
            MCRYPT_MODE_CFB,
            MCRYPT_MODE_ECB,
            MCRYPT_MODE_OFB,
            MCRYPT_MODE_NOFB,
        );
    }
    
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
        $rbyte = \Dcrypt\Random::bytes(1);
        if ($byte === $rbyte) {
            $rbyte = (ord($rbyte) + 1) % 256;
            $rbyte = chr($rbyte);
        }
        $inp[$off] = $rbyte;
        // @codeCoverageIgnoreEnd
        return implode($inp);
    }
}
