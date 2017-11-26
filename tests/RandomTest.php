<?php

class RandomTest extends \PHPUnit\Framework\TestCase
{
    public function testBytes()
    {
        $len = 10;

        $m = \Dcrypt\Random::bytes($len);
        
        $this->assertTrue(strlen($m) === $len);
    }
    
    public function testShuffle()
    {
        $array = array('a', 'b', 'c', 'd');

        $array = \Dcrypt\Random::shuffle($array, 'seed string can be any length because it is hashed before use', false);
        
        $this->assertEquals('b', array_shift($array));
        $this->assertEquals('a', array_shift($array));
        $this->assertEquals('c', array_shift($array));
        $this->assertEquals('d', array_shift($array));
    }
}
