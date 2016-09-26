<?php

use Dcrypt\Aes;
use Dcrypt\Mcrypt;

class AesTest extends TestSupport
{

    public function testCrossCompatability()
    {
        $k = 'asdf';
        $p = '1234';
        $c = Aes::encrypt($p, $k);
        $this->assertEquals($p, Mcrypt::decrypt($c, $k));
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testPbkdf()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = Aes::encrypt($input, $key, 10);
        $this->assertEquals($input, Aes::decrypt($encrypted, $key, 10));

        $corrupt = \Dcrypt\Support\TestSupport::swaprandbyte($encrypted);
        Aes::decrypt($corrupt, $key, 10);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testEngine()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';

        $encrypted = Aes::encrypt($input, $key);
        $this->assertEquals($input, Aes::decrypt($encrypted, $key));

        // Perform a validation by replacing a random byte to make sure
        // the decryption fails. After enough successful runs,
        // all areas of the cypher text will have been tested
        // for integrity
        $corrupt = \Dcrypt\Support\TestSupport::swaprandbyte($encrypted);
        Aes::decrypt($corrupt, $key);
    }

    public function testVector()
    {
        $input = 'hello world';
        $pass = 'password';
        $vector = \base64_decode('eZu2DqB2gYhdA2YkjagLNJJVMVo1BbpJ75tW/PO2bGIY98XHD+Gp+YlO5cv/rHzo45LHMCxL2qOircdST1w5hg==');

        $this->assertEquals($input, Aes::decrypt($vector, $pass));
    }

}
