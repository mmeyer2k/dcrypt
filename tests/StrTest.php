<?php
use Dcrypt\Str;

class StrcmpTest extends PHPUnit_Framework_TestCase
{
    public function testSpecial()
    {
        // This function tests the conditional type casting of the
        // user input in str::equal
        $this->assertTrue(Str::equal('2222', 2222));
    }
}
