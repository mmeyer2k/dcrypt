<?php

use Dcrypt\Hash;

class HashTest extends \PHPUnit\Framework\TestCase
{
    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'f1q8GdPqYfZsuXi8DoGT77/8VTyhaKt6AAAD6N7D09XWWzOSpRfm4EILjorgxgZ+sMqP/9XEhLYGvkcb',
        'M7cCWrAuwo10HBC/UvMX87/8VTyhaKt6AAAD6KLVDKta4WVMUPA2/pale0JxnDQLNzFcOALbX/tfOZLr',
        'cXqhFyGAJKKuMaoW85aKaL/8VTyhaKt6AAAD6D2aLd5jAEvme9r5hizmYsHP3KqazE0uYNWfysk3AoSJ',
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

    public function testVectors()
    {
        #echo base64_encode(Hash::make(self::$input, self::$key, 1000));
        foreach (self::$vectors as $vector) {
            $vector = base64_decode($vector);
            $this->assertTrue(Hash::verify(self::$input, $vector, self::$key));
        }
    }
}
