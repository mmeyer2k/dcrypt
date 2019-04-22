<?php

use Dcrypt\AesCbc;

class AesCbcTest extends TestSupport
{
    public $vectors = [
        '',
        '',
        '',
    ];

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

    public function testEngine3()
    {
        $input = \random_bytes(16);
        $key = \random_bytes(256);

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

        $corrupt = self::swaprandbyte($encrypted);
        AesCbc::decrypt($corrupt, $key);
    }
}
