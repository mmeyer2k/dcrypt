<?php

class RandomTest extends PHPUnit_Framework_TestCase
{

    public function testGet()
    {
        $len = 10;
    
        $m = \Dcrypt\Random::get($len);
        $this->assertTrue(strlen($m) === $len);
    }
    
}
