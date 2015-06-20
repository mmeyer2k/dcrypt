<?php

use \Dcrypt\Openssl;

require __DIR__ . '/../helpers/swaprandbyte.php';

class OpensslTest extends PHPUnit_Framework_TestCase
{

    public function testPkdf()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = Openssl::encrypt($input, $key, 10);
        $this->assertEquals($input, Openssl::decrypt($encrypted, $key, 10));

        $corrupt = swaprandbyte($encrypted);
        $this->assertFalse(Openssl::decrypt($corrupt, $key, 10));
    }

    public function testEngine()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';

        $encrypted = Openssl::encrypt($input, $key);
        $this->assertEquals($input, Openssl::decrypt($encrypted, $key));

        // Perform a validation by replacing a random byte to make sure
        // the decryption fails. After enough successful runs,
        // all areas of the cypher text will have been tested
        // for integrity
        $corrupt = swaprandbyte($encrypted);
        $this->assertFalse(Openssl::decrypt($corrupt, $key));
    }

    public function testVector()
    {
        $input = 'hello world';
        $pass = 'password';
        $vector = base64_decode('BwjqDdmriMTni8Cqs1N8kbtV7fdC1e9VSWGLa75NoTVdKvGfZ0q2fjPFDllKikOtiUyzNRN4k42XnqI/2U+5LA==');
        
        $this->assertEquals($input, Openssl::decrypt($vector, $pass, 10));
    }

}
