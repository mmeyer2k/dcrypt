<?php

use Dcrypt\Pkcs7;

class Pkcs7Test extends PHPUnit_Framework_TestCase
{

    public function testPad()
    {
        foreach (self::arraySet() as $t) {
            $this->assertEquals($t[1], strlen(Pkcs7::pad($t[0], 32)));
        }
    }

    public function testUnpad()
    {
        foreach (self::arraySet() as $t) {
            $padded = Pkcs7::pad($t[0], 10);
            $this->assertEquals($t[0], Pkcs7::unpad($padded, 10));
        }
    }

    private static function arraySet()
    {
        return array(
            array('', 32),
            array(null, 32),
            array('A', 32),
            array('AAAA', 32),
            array('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 32),
            array('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 32),
            array('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 64),
            array('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 64),
            array(str_repeat('A', 10000), 10016)
        );
    }

}
