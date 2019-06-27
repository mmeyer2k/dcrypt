<?php declare(strict_types=1);

class AesBase extends \PHPUnit\Framework\TestCase
{
    public static $input = 'AAAAAAAA';
    public static $password = 'BBBBBBBBCCCCCCCC';
    public static $key = 'eXy/tXzysbiAqyLHnXnaFEJoTDl3faDVq148M5ACiavzgeiwXHw2QWDoBvLJ/nUV+hPaCqRzuwWmoxn4RsaA3RnnU0IQnumF4mLkb71d3PV/c7DcpJ935Mhd34uH9xaPmbkmy3ikl6Eakqix020nuHBPvR7RAiYrcZschUGlFYk=';

    public function testEngineWithPassword()
    {
        $encrypted = static::$class::encrypt(self::$input, self::$password, 10000);
        $decrypted = static::$class::decrypt($encrypted, self::$password, 10000);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngineWithKey()
    {
        $key = base64_decode(self::$key);

        $encrypted = static::$class::encrypt(self::$input, $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngineWithSomeRandomness()
    {
        $input = \random_bytes(256);
        $key = \random_bytes(256);

        $encrypted = static::$class::encrypt($input, $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }
    
    public function testCorruptDataUsingKey()
    {
        $key = base64_decode(self::$key);

        $encrypted = static::$class::encrypt(self::$input, $key);

        $this->assertEquals(self::$input, static::$class::decrypt($encrypted, $key));

        $this->expectException(\Dcrypt\Exceptions\InvalidChecksum::class);

        static::$class::decrypt($encrypted . 'A', $key);
    }

    public function testCorruptDataUsingPassword()
    {
        $encrypted = static::$class::encrypt(self::$input, self::$key);

        $this->assertEquals(self::$input, static::$class::decrypt($encrypted, self::$key));

        $this->expectException(\Dcrypt\Exceptions\InvalidChecksum::class);

        static::$class::decrypt($encrypted . 'A', self::$key);
    }
}
