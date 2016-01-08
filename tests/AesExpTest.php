<?php

use Dcrypt\AesExp;
use Dcrypt\Support\Support;

class AesExpTest extends PHPUnit_Framework_TestCase
{

    /**
     * @expectedException InvalidArgumentException
     */
    public function testException()
    {
        $input = $key = str_repeat('A', 10000);
        $encrypted = AesExp::encrypt($input, $key, 10);

        $corrupt = Support::swaprandbyte($encrypted);

        AesExp::decrypt($corrupt, $key, 10);
    }

}
