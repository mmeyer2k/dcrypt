<?php declare(strict_types=1);

use Dcrypt\Rot128;

class Rot128Test extends \PHPUnit\Framework\TestCase
{
    public function testRotate()
    {
        $a = Rot128::flip('asdf');
        $b = Rot128::flip($a);
        $this->assertEquals('asdf', $b);
    }

    public function testKnown()
    {
        $a = Rot128::flip(hex2bin('e1e2e3e4'));
        $this->assertEquals('abcd', $a);
    }

    public function testRandom()
    {
        $r = \random_bytes(1024);
        $a = Rot128::flip($r);
        $b = Rot128::flip($a);
        $this->assertEquals($r, $b);
    }
}
