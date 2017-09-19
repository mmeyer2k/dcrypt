<?php

class HuffmanTest extends \PHPUnit\Framework\TestCase
{
    public function testSwap()
    {
        foreach (range(1, 20) as $r) {
            $a = \Dcrypt\Random::bytes($r);
            $b = \Dcrypt\Huffman::encode($a);
            $c = \Dcrypt\Huffman::decode($b);
            $this->assertEquals($a, $c);
        }
    }
}
