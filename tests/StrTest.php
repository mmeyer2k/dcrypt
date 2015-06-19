<?php
use Dcrypt\Str;

class StrcmpTest extends PHPUnit_Framework_TestCase
{
    public function testSpecial()
    {
        Str::equal(1, '1234');
    }
}
