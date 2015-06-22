<?php

use Dcrypt\Hash;

require __DIR__ . '/../helpers/swaprandbyte.php';

class HashTest extends PHPUnit_Framework_TestCase
{

    public function testIhmacSanity()
    {
        // Make sure at least one hash always happens with any kind of crazy cost value
        $this->assertNotEquals('aaaa', Hash::ihmac('aaaa', 'bbbb', 0));
        $this->assertNotEquals('aaaa', Hash::ihmac('aaaa', 'bbbb', -1));
    }

    public function testBadCost()
    {
        $this->assertEquals(64, strlen(Hash::make('test', '1234', 0)));
    }

    public function testLength()
    {
        $this->assertEquals(64, strlen(Hash::make('test', '1234')));
    }

    public function testCycle()
    {
        $input = 'input test';
        $key = 'key123';
        $hash = Hash::make($input, $key, 1);
        $this->assertTrue(Hash::verify($input, $hash, $key));
    }

    public function testFail()
    {
        $input = str_repeat('A', rand(0, 10000));
        $key = str_repeat('A', rand(10, 100));
        $cost = 1;

        $output = Hash::make($input, $key, $cost);
        $this->assertTrue(Hash::verify($input, $output, $key));

        for ($i = 0; $i < 10; $i++) {
            $corrupt = swaprandbyte($output);
            $this->assertFalse(Hash::verify($input, $corrupt, $key));
        }
    }

    public function testVector()
    {
        $input = 'hello world';
        $key = 'password';
        $vector = base64_decode('gEUEz00qsG1Df50gzjZcquvgb39b6F+Kd4r+3I7KHNzl6ON7GG22bcTVN1MDTzngSzp6tpH+QB/FBR3ZmaYnrw==');
        $this->assertTrue(Hash::verify($input, $vector, $key));
    }

}
