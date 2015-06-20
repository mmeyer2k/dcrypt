<?php

use Dcrypt\Hash;

require __DIR__ . '/../helpers/swaprandbyte.php';

class HashTest extends PHPUnit_Framework_TestCase
{

    public function testLength()
    {
        $this->assertEquals(64, strlen(Hash::make('test', '1234')));
    }

    public function testRange()
    {
        $i = 'input test';
        $k = 'key123';
        foreach (array(1, 10, 15) as $i) {
            $hash = Hash::make($i, $k, $i);
            $this->assertTrue(Hash::verify($i, $hash, $k));
        }
    }

    public function testFail()
    {
        $input = str_repeat('A', rand(0, 10000));
        $key = str_repeat('A', rand(10, 100));
        $cost = 2;

        $output = Hash::make($input, $key, $cost);

        for ($i = 0; $i < 10; $i++) {
            $corrupt = swaprandbyte($output);
            $this->assertFalse(Hash::verify($input, $corrupt, $key));
        }
    }

}
