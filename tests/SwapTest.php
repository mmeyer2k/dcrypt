<?php

require __DIR__ . '/../helpers/swaprandbyte.php';

class SwapTest extends PHPUnit_Framework_TestCase
{

    public function testSwap()
    {
        $orig = 'AAAAAAAAAA';
        for ($i = 0; $i < 500; $i = $i + 5) {
            $this->assertFalse($orig === swaprandbyte($orig));
            $this->assertEquals(levenshtein($orig, swaprandbyte($orig)), 1);
        }
    }

}
