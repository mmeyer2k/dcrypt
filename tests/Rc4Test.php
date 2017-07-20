<?php

use Dcrypt\Rc4;

class Rc4Test extends \PHPUnit\Framework\TestCase
{
    public function testCrypt()
    {
        $input = openssl_random_pseudo_bytes(256);
        $key = openssl_random_pseudo_bytes(32);

        /*
         * Test encryption
         */
        $encrypted = Rc4::crypt($input, $key);
        $this->assertEquals(strlen($input), strlen($encrypted));
        $this->assertNotEquals($input, $encrypted);

        /*
         * Test decryption
         */
        $decrypted = Rc4::crypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }

    public function testVector()
    {
        /*
         * Test that known cypher text decrypts properly
         */
        $cyphertext = hex2bin('140ad3d278a229ff3c487d');
        $plain = 'Hello World';
        $key = 'asdf';

        $this->assertEquals($plain, Rc4::crypt($cyphertext, $key));
    }
}
