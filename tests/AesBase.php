<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidChecksumException;
use Dcrypt\Exceptions\InvalidKeyEncodingException;
use Dcrypt\OpensslKey;

class AesBase extends \PHPUnit\Framework\TestCase
{
    public function testEngineInKeyMode()
    {
        $key = OpensslKey::create();

        $encrypted = static::$class::encrypt('a secret', $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals('a secret', $decrypted);
    }

    public function testEngineWithSomeRandomnessWhileInKeyMode()
    {
        $input = random_bytes(256);
        $key = OpensslKey::create();

        $encrypted = static::$class::encrypt($input, $key);
        $decrypted = static::$class::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testCorruptDataUsingKeyMode()
    {
        $key = OpensslKey::create();

        $encrypted = static::$class::encrypt('a secret', $key);

        $this->assertEquals('a secret', static::$class::decrypt($encrypted, $key));

        $this->expectException(InvalidChecksumException::class);

        static::$class::decrypt($encrypted . 'A', $key);
    }

    public function testInvalidKeyEncoding()
    {
        $this->expectException(InvalidKeyEncodingException::class);

        $crazyKey = str_repeat('?', 10000);

        static::$class::encrypt('a secret', $crazyKey);
    }

    public function testNameMatch()
    {
        // Make sure that the name has the cipher in it so that there can never be a mismatch between
        // the name of the cipher and the cipher given to openssl
        $testname1 = strtolower(str_replace('-', '', static::$class::CIPHER));
        $testname2 = strtolower(static::$class);

        $this->assertTrue(strpos($testname2, $testname1) > 0);
    }

    public function testKnownVector()
    {
        // Skip if PHP 7.1 and CCM mode. Implementation in Openssl was fixed but never backported it seems...
        if (PHP_MAJOR_VERSION . PHP_MINOR_VERSION === '71' && strpos(static::$class, 'Ccm')) {
            return $this->assertTrue(true);
        }

        // Decode the vectors json
        $json = json_decode(file_get_contents(__DIR__ . '/.vectors.json'));

        // Gather the generated payload for this cipher
        $c = $json->aes256->{static::$class};

        // Run the decryption with the provided key
        $d = static::$class::decrypt(base64_decode($c), $json->key);

        // Assert that the payload decoded correctly
        $this->assertEquals('a secret', $d);
    }
}
