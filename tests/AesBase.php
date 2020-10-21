<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

class AesBase extends \PHPUnit\Framework\TestCase
{
    public function testEngineInKeyMode()
    {
        $key = \Dcrypt\OpensslKey::create();

        $encrypted = static::$class::encrypt('a secret', $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals('a secret', $decrypted);
    }

    public function testEngineWithSomeRandomnessWhileInKeyMode()
    {
        $input = random_bytes(256);
        $key = \Dcrypt\OpensslKey::create();

        $encrypted = static::$class::encrypt($input, $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testCorruptDataUsingKeyMode()
    {
        $key = \Dcrypt\OpensslKey::create();

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

    public function testNameMatch()
    {
        // Make sure that the name has the cipher in it so that there can never be a mismatch between
        // the name of the cipher and the cipher given to openssl
        $testname1 = strtolower(str_replace('-', '', static::$class::CIPHER));
        $testname2 = strtolower(static::$class);

        $this->assertTrue(strpos($testname1, $testname2) > 0);
    }

    public function testKnownVector()
    {
        $json = json_decode(file_get_contents(__DIR__ . '/.vectors.json'));
        $c = $json->aes256->{static::$class};
        $d = static::$class::decrypt(base64_decode($c), $json->key);
        $this->assertEquals('a secret', $d);
    }
}
