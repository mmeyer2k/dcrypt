<?php
use Dcrypt\Str;

class StrcmpTest extends PHPUnit_Framework_TestCase
{
    public function testSpecial()
    {
        // This function tests the conditionals from symfony
        $this->assertTrue(Str::equal('2222', 2222));
        $this->assertTrue(Str::equal(2222, '2222'));
        
        // Test without hash_equals
        $this->assertTrue(Str::equal('2222', '2222', false));
    }
}
