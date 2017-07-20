<?php

class SwapTest extends TestSupport
{
    public function testSwap()
    {
        $orig = 'AAAAAAAAAA';
        for ($i = 0; $i < 10; $i = $i + 5) {
            $this->assertFalse($orig === self::swaprandbyte($orig));
            $this->assertEquals(levenshtein($orig, self::swaprandbyte($orig)), 1);
        }
    }
}
