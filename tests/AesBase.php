<?php declare(strict_types=1);

class AesBase extends \PHPUnit\Framework\TestCase
{
    public static $input = 'AAAAAAAA';
    public static $key = 'BBBBBBBBCCCCCCCC';

    public function testEngine1()
    {
        $encrypted = static::$class::encrypt(self::$input, self::$key, 10000);
        $decrypted = static::$class::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine2()
    {
        $encrypted = static::$class::encrypt(self::$input, self::$key);
        $decrypted = static::$class::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine3()
    {
        $input = \random_bytes(16);
        $key = \random_bytes(256);

        $encrypted = static::$class::encrypt($input, $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testCorrupt()
    {
        $encrypted = static::$class::encrypt(self::$input, self::$key, 10000);

        // Validate that the blob will decrypt
        $this->assertEquals(self::$input, static::$class::decrypt($encrypted, self::$key));

        $this->expectException(static::$class::decrypt($encrypted . 'A', self::$key));
    }
}
