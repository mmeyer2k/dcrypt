<?php

use Dcrypt\Str;

class StrcmpTest extends PHPUnit_Framework_TestCase
{

    public function testEquals()
    {
        // This function tests the conditionals from symfony
        $this->assertTrue(Str::equal('2222', 2222));
        $this->assertTrue(Str::equal(2222, '2222'));

        // Test falseness
        $this->assertFalse(Str::equal('2222', '3333', true));

        // Test without hash_equals
        $this->assertTrue(Str::equal('2222', '2222', false));
        $this->assertFalse(Str::equal('2222', '3333', false));
    }

}
