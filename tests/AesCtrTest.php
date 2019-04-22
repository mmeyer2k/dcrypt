<?php

use Dcrypt\AesCtr;

class AesCtrTest extends TestSupport
{
    public function testEngine1()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCtr::encrypt($input, $key, 10000);
        $decrypted = AesCtr::decrypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }

    public function testEngine2()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCtr::encrypt($input, $key);
        $decrypted = AesCtr::decrypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';

        $encrypted = AesCtr::encrypt($input, $key, 10000);
        $this->assertEquals($input, AesCtr::decrypt($encrypted, $key));

        // Perform a validation by replacing a random byte to make sure
        // the decryption fails. After enough successful runs,
        // all areas of the cypher text will have been tested
        // for integrity
        $corrupt = self::swaprandbyte($encrypted);
        AesCtr::decrypt($corrupt, $key);
    }
}
