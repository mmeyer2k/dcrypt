<?php

use Dcrypt\Hash;

class HashTest extends \PHPUnit\Framework\TestCase
{
    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'NfX/5CuGPZu6YJUetAhpK7/8VTyhaKt6krIsqUPFxq3K4EcSyRL9Pj8VCj4oSjUAAAAD6N9fcLz676xz881zcE4qM2fIDOBdEVK3sOhraDV9qy7J',
    ];

    public function testBuild1()
    {
        $h = Hash::make('AAAA', 'BBBB', 100);

        $this->assertEquals(60, strlen($h));

        $this->assertTrue(Hash::verify('AAAA', $h, 'BBBB'));
    }

    public function testBuild2()
    {
        $h = Hash::make(self::$input, self::$key);

        $this->assertEquals(60, strlen($h));

        $this->assertTrue(Hash::verify(self::$input, $h, self::$key));
    }

    public function testBuild3()
    {
        $h = Hash::make(self::$input, self::$key, 100);

        $this->assertEquals(60, strlen($h));
    }

    public function testBuildFail1()
    {
        $h = Hash::make('AAAA', 'BBBB', 100);

        $this->assertFalse(Hash::verify('AAAA', $h, 'CCCC'));
    }

    /*
    public function testVectors()
    {
        foreach (self::$vectors as $vector) {
            #echo base64_encode(Hash::make(self::$input, self::$key, 1000));
            #$this->assertTrue(Hash::verify(self::$input, base64_decode($vector), self::$key));
        }
    }
    */
}
