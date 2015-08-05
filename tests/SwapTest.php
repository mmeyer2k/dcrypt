<?php

class SwapTest extends PHPUnit_Framework_TestCase
{

    public function testSwap()
    {
        $orig = 'AAAAAAAAAA';
        for ($i = 0; $i < 10; $i = $i + 5) {
            $this->assertFalse($orig === \Dcrypt\Support\Support::swaprandbyte($orig));
            $this->assertEquals(levenshtein($orig, \Dcrypt\Support\Support::swaprandbyte($orig)), 1);
        }
    }

}
