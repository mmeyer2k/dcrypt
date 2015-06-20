<?php

class RandomTest extends PHPUnit_Framework_TestCase
{

    public function testGet()
    {
        $len = 2;
    
        $m = \Dcrypt\Random::get($len, true);
        $this->assertTrue(strlen($m) === $len);
        
        $o = \Dcrypt\Random::get($len, false);
        $this->assertTrue(strlen($o) === $len);
    }
    
}
