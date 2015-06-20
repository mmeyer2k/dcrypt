<?php

use Dcrypt\Aes;
use Dcrypt\Mcrypt;
use Dcrypt\Openssl;

class AesTest extends PHPUnit_Framework_TestCase
{

    public function testCrossCompatability()
    {
        $k = 'asdf';
        $p = '1234';
        $c = Openssl::encrypt($p, $k);
        $this->assertEquals($p, Mcrypt::decrypt($c, $k));
    }

}
