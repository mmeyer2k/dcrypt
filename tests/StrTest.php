<?php

use Dcrypt\Str;

class StrcmpTest extends \PHPUnit\Framework\TestCase
{
    public function testEquals()
    {
        // Test with hash_equals
        $this->assertTrue(Str::equal('2222', '2222', true));
        $this->assertFalse(Str::equal('2222', '3333', true));

        // Test without hash_equals
        $this->assertTrue(Str::equal('2222', '2222', false));
        $this->assertFalse(Str::equal('2222', '3333', false));
    }
}
