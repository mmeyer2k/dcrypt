<?php

use Dcrypt\Hash;

class HashTest extends \PHPUnit\Framework\TestCase
{
    public static $vectors = [
        '',
        '',
        '',
    ];

    public function testBuild1()
    {
        $h = Hash::make('AAAA', 'BBBB', 100);

        $this->assertTrue(strlen($h) === 52);

        $this->assertTrue(Hash::verify('AAAA', $h, 'BBBB'));
    }

    public function testBuild2()
    {
        $h = Hash::make('AAAA', 'BBBB');

        $this->assertTrue(strlen($h) === 52);

        $this->assertTrue(Hash::verify('AAAA', $h, 'BBBB'));
    }

    public function testBuildFail1()
    {
        $h = Hash::make('AAAA', 'BBBB', 100);

        $this->assertFalse(Hash::verify('AAAA', $h, 'CCCC'));
    }
}
