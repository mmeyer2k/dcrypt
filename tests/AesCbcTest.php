<?php

use Dcrypt\AesCbc;

class AesCbcTest extends TestSupport
{
    public function testEngine1()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCbc::encrypt($input, $key, 100);
        $decrypted = AesCbc::decrypt($encrypted, $key);
        $this->assertEquals($input, $decrypted);
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testEngine2()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';

        $encrypted = AesCbc::encrypt($input, $key);
        $this->assertEquals($input, AesCbc::decrypt($encrypted, $key));

        // Perform a validation by replacing a random byte to make sure
        // the decryption fails. After enough successful runs,
        // all areas of the cypher text will have been tested
        // for integrity
        #$corrupt = self::swaprandbyte($encrypted);
        #AesCbc::decrypt($corrupt, $key);
    }

    /*
    public function testVector()
    {
        $input = 'hello world';
        $pass = 'password';
        $vector = \base64_decode('eZu2DqB2gYhdA2YkjagLNJJVMVo1BbpJ75tW/PO2bGIY98XHD+Gp+YlO5cv/rHzo45LHMCxL2qOircdST1w5hg==');

        $this->assertEquals($input, AesCbc::decrypt($vector, $pass));
    }
    */
}
