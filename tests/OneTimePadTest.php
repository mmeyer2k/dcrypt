<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\OneTimePad;

class OneTimePadTest extends \PHPUnit\Framework\TestCase
{
    public function testCrypt()
    {
        $key = \Dcrypt\OpensslKey::create();

        foreach (range(1, 1000, 100) as $mult) {
            $input = str_repeat('A', 4 * $mult);

            $encrypted = OneTimePad::crypt($input, $key);

            $this->assertEquals(strlen($input), strlen($encrypted));
            $this->assertNotEquals($input, $encrypted);

            $decrypted = OneTimePad::crypt($encrypted, $key);
            $this->assertEquals($input, $decrypted);
        }
    }

    public function testVector()
    {
        $json = json_decode(file_get_contents(__DIR__ . '/.vectors.json'));

        foreach ($json->otp as $mult => $data) {
            $data = base64_decode($data);
            $expected = str_repeat('A', (int) $mult);
            $this->assertEquals($expected, OneTimePad::crypt($data, $json->key));
        }
    }
}
