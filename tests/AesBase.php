<?php declare(strict_types=1);

namespace Dcrypt\Tests;

class AesBase extends \PHPUnit\Framework\TestCase
{
    public function testEngineInKeyMode()
    {
        $key = \Dcrypt\OpensslKeyGenerator::newKey();

        $encrypted = static::$class::encrypt('a secret', $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals('a secret', $decrypted);
    }

    public function testEngineWithSomeRandomnessWhileInKeyMode()
    {
        $input = \random_bytes(256);
        $key = \Dcrypt\OpensslKeyGenerator::newKey();

        $encrypted = static::$class::encrypt($input, $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testCorruptDataUsingKeyMode()
    {
        $key = \Dcrypt\OpensslKeyGenerator::newKey();

        $encrypted = static::$class::encrypt('a secret', $key);

        $this->assertEquals('a secret', static::$class::decrypt($encrypted, $key));

        $this->expectException(\Dcrypt\Exceptions\InvalidChecksumException::class);

        static::$class::decrypt($encrypted . 'A', $key);
    }

    public function testInvalidKeyEncoding()
    {
        $this->expectException(\Dcrypt\Exceptions\InvalidKeyException::class);

        $crazyKey = str_repeat('?', 10000);

        static::$class::encrypt('a secret', $crazyKey);
    }
}
