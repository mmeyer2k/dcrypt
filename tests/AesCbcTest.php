<?php

use Dcrypt\AesCbc;

class AesCbcTest extends TestSupport
{
    public function testEngine1()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCbc::encrypt($input, $key, 10000);
        $decrypted = AesCbc::decrypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }

    public function testEngine2()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCbc::encrypt($input, $key);
        $decrypted = AesCbc::decrypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';

        $encrypted = AesCbc::encrypt($input, $key, 10000);
        $this->assertEquals($input, AesCbc::decrypt($encrypted, $key));

        // Perform a validation by replacing a random byte to make sure
        // the decryption fails. After enough successful runs,
        // all areas of the cypher text will have been tested
        // for integrity
        $corrupt = self::swaprandbyte($encrypted);
        AesCbc::decrypt($corrupt, $key);
    }
}
