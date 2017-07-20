<?php

use Dcrypt\Pkcs7;

class Pkcs7Test extends \PHPUnit\Framework\TestCase
{
    public function testVectors()
    {
        $this->assertEquals(Pkcs7::pad('aaaabbbb', 3), "aaaabbbb\x01");

        $this->assertEquals(Pkcs7::pad('aaaabbbb', 4), "aaaabbbb\x04\x04\x04\x04");

        $this->assertEquals(Pkcs7::unpad("aaaabbbb\x01"), "aaaabbbb");

        $this->assertEquals(Pkcs7::unpad("aaaabbbb\x04\x04\x04\x04"), "aaaabbbb");
    }
}
