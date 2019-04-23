<?php

use Dcrypt\AesCtr;

class AesCtrTest extends \PHPUnit\Framework\TestCase
{
    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'E4M3ierx8R27AudHgecE3r42KxLe9qd85AKG1wYo94rVzJ+adUgZdjS6yY9/T2XjlqsDk1qabES74VXQ',
        'fysIOWwcwB/y07sxrV6njouA/TxKsNkfifVjJRVP/SolO2Q2N3f0ULOTUpMOlKgEO0esEEzp+pgDKjf6',
        '+VUBy1RRV+dg/o3LLuau562McjWNNCguTwVoB/SG96t8HuU7xR4i/Yi5K/uAzFO8VYPQxNBduuA3zeR0',
    ];

    public function testEngine1()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key, 10000);
        $decrypted = AesCtr::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine2()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key);
        $decrypted = AesCtr::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine3()
    {
        $input = \random_bytes(16);
        $key = \random_bytes(256);

        $encrypted = AesCtr::encrypt($input, $key);
        $decrypted = AesCtr::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testVectors()
    {
        //var_dump(base64_encode(AesCtr::encrypt(self::$input, self::$key)));
        foreach (self::$vectors as $vector) {
            $decrypted = AesCtr::decrypt(base64_decode($vector), self::$key);
            $this->assertEquals(self::$input, $decrypted);
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key, 1);
        $this->assertEquals(self::$input, AesCtr::decrypt($encrypted, self::$key));
        AesCtr::decrypt($encrypted . 'A', self::$key);
    }
}
