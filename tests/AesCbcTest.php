<?php

use Dcrypt\AesCbc;

class AesCbcTest extends \PHPUnit\Framework\TestCase
{
    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'TBKxhZZceWusumsstOpaBV+RA26sb9S5CXF5bMM16fZ4fuJG0JU8wHBTcwRyX/8fu2ILrsKVfxbzuUeHRQ6GX6ad1ZI=',
        'oNINffRHwsdox/XPs8HOGo1FvQx+0YylEmgYyQsQMCdm8TgeGC3b+D2uJKBxoBI2Z82/rn3PAgBhsbdeMYX/26z2nA0=',
        'Dd8n0dRlRap79mkRBQVDwnHVhD3AdME19mSiRIiwgtgMfqXEiGjzCP2HU8F0weTLFTJlW2h1KyGQ6kjmu2Xm2s13Tx4=',
    ];

    public function testEngine1()
    {
        $encrypted = AesCbc::encrypt(self::$input, self::$key, 10000);
        $decrypted = AesCbc::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine2()
    {
        $encrypted = AesCbc::encrypt(self::$input, self::$key);
        $decrypted = AesCbc::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine3()
    {
        $input = \random_bytes(16);
        $key = \random_bytes(256);

        $encrypted = AesCbc::encrypt($input, $key);
        $decrypted = AesCbc::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testVectors()
    {
        //var_dump(base64_encode(AesCbc::encrypt(self::$input, self::$key)));
        foreach (self::$vectors as $vector) {
            $decrypted = AesCbc::decrypt(base64_decode($vector), self::$key);
            $this->assertEquals(self::$input, $decrypted);
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $encrypted = AesCbc::encrypt(self::$input, self::$key, 10000);
        $this->assertEquals(self::$input, AesCbc::decrypt($encrypted, self::$key));
        AesCbc::decrypt($encrypted . 'A', self::$key);
    }
}
