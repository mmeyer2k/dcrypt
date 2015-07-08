<?php

use Dcrypt\Aes;
use Dcrypt\Mcrypt;

class AesTest extends PHPUnit_Framework_TestCase
{

    public function testCrossCompatability()
    {
        $k = 'asdf';
        $p = '1234';
        $c = Aes::encrypt($p, $k);
        $this->assertEquals($p, Mcrypt::decrypt($c, $k));
    }

    public function testPbkdf()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = Aes::encrypt($input, $key, 10);
        $this->assertEquals($input, Aes::decrypt($encrypted, $key, 10));

        $corrupt = swaprandbyte($encrypted);
        $this->assertFalse(Aes::decrypt($corrupt, $key, 10));
    }

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
        $corrupt = swaprandbyte($encrypted);
        $this->assertFalse(Aes::decrypt($corrupt, $key));
    }

    public function testVector()
    {
        $input = 'hello world';
        $pass = 'password';
        $vector = \base64_decode('BwjqDdmriMTni8Cqs1N8kbtV7fdC1e9VSWGLa75NoTVdKvGfZ0q2fjPFDllKikOtiUyzNRN4k42XnqI/2U+5LA==');

        $this->assertEquals($input, Aes::decrypt($vector, $pass, 10));
    }

}
