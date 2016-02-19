<?php

class RandomTest extends PHPUnit_Framework_TestCase
{

    public function testGet()
    {
        $len = 10;
    
        $m = \Dcrypt\Random::bytes($len);
        $this->assertTrue(strlen($m) === $len);
    }
    
}
