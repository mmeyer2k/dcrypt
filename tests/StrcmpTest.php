<?php
use Dcrypt\Strcmp;

class StrcmpTest extends PHPUnit_Framework_TestCase
{
    public function testSpecial()
    {
        Strcmp::equals(1, '1234');
    }
}
