<?php

use Dcrypt\AesCtr;

class AesCtrTest extends TestSupport
{

    private static $input = 'AAAAAAAA';
    private static $key = 'AAAAAAAA';

    public static $vectors = [
        'XFZwvXOd79A2Jvnog9eLaoPX7T8gXHFKJJ1GqDi1Mb3ZkyAy9BbnCawJyMyXySEJOWkTVrgf71yyN9MF',
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
        foreach (self::$vectors as $vector) {
            #var_dump(base64_encode(AesCtr::encrypt(self::$input, self::$key)));
            $decrypted = AesCtr::decrypt(base64_decode($vector), self::$key);
            $this->assertEquals(self::$input, $decrypted);
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key, 10000);
        $this->assertEquals(self::$input, AesCtr::decrypt($encrypted, self::$key));

        $corrupt = self::swaprandbyte($encrypted);
        AesCtr::decrypt($corrupt, self::$key);
    }
}
