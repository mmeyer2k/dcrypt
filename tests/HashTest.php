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
        $input = 'input test';
        $key = 'key123';
        foreach (array(1, 10) as $cost) {
            $hash = Hash::make($input, $key, $cost);
            $this->assertTrue(Hash::verify($input, $hash, $key));
        }
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
        $vector = base64_decode('6rI7U95Tmtvn+tG6P7FjKDrAIZXNrJMklZTmMpGXB9eO3Xy8pL71PaZXV3M10Mh/78tgXBhYoDNvG2DcVfwekQ==');
        $this->assertTrue(Hash::verify($input, $vector, $key));
    }

}
