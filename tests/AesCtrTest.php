<?php

use Dcrypt\AesCtr;

class AesCtrTest extends PHPUnit_Framework_TestCase
{

    /**
     * @expectedException InvalidArgumentException
     */
    public function testPbkdf()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCtr::encrypt($input, $key, 10);
        $this->assertEquals($input, AesCtr::decrypt($encrypted, $key, 10));
        $corrupt = \Dcrypt\Support\Support::swaprandbyte($encrypted);
        $this->assertFalse(AesCtr::decrypt($corrupt, $key, 10));
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testEngine()
    {
        $input = 'AAAAAAAA';
        $key = 'AAAAAAAA';
        $encrypted = AesCtr::encrypt($input, $key);
        $this->assertEquals($input, AesCtr::decrypt($encrypted, $key));
        // Perform a validation by replacing a random byte to make sure
        // the decryption fails. After enough successful runs,
        // all areas of the cypher text will have been tested
        // for integrity
        $corrupt = \Dcrypt\Support\Support::swaprandbyte($encrypted);
        AesCtr::decrypt($corrupt, $key);
    }

    public function testVector()
    {
        $input = 'hello world';
        $pass = 'password';
        $vector = \base64_decode('MwlJBe8qCGbM25/O3HUtJKL3P0QJjDh1/uZIEAHh3E3Btd3CH8NGlRos8Ns+iAw0/d80vYIPkYJvcEQCVIKO3A==');
        $this->assertEquals($input, AesCtr::decrypt($vector, $pass));
    }

}
