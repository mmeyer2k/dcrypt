<?php

class RandomTest extends \PHPUnit\Framework\TestCase
{
    public function testGet()
    {
        $len = 10;
    
        $m = \Dcrypt\Random::bytes($len);
        $this->assertTrue(strlen($m) === $len);
    }
}
