<?php

use Dcrypt\Spritz;

class SpritzTest extends \PHPUnit\Framework\TestCase
{
    public function testCrypt()
    {
        $input = 'AAAAAAAA';
        $key = openssl_random_pseudo_bytes(32);

        /*
         * Test encryption
         */
        $encrypted = Spritz::crypt($input, $key);
        $this->assertEquals(strlen($input), strlen($encrypted));
        $this->assertNotEquals($input, $encrypted);

        /*
         * Test decryption
         */
        $decrypted = Spritz::crypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }
}
