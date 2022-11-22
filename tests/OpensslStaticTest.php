<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidChecksumException;
use Dcrypt\OpensslKey;
use Dcrypt\OpensslStatic;
use Exception;
use PHPUnit\Framework\TestCase;
use ValueError;

class OpensslStaticTest extends TestCase
{
    public function testVectorsAlgos()
    {
        $json = file_get_contents(__DIR__ . '/.vectors.json');

        $json = json_decode($json);

        foreach ($json->algos as $algo => $data) {
            try {
                $plaintext = OpensslStatic::decrypt(base64_decode($data), $json->key, 'aes-256-gcm', $algo);
            } catch (Exception|\Error $e) {
            }

            $this->assertEquals('a secret', $plaintext);
        }
    }

    public function testVectorsCiphers()
    {
        $json = file_get_contents(__DIR__ . '/.vectors.json');

        $json = json_decode($json);

        foreach ($json->ciphers as $cipher => $data) {
            try {
                $plaintext = OpensslStatic::decrypt(base64_decode($data), $json->key, $cipher, 'sha3-256');
            } catch (Exception|\Error $e) {
            }

            $this->assertEquals('a secret', $plaintext);
        }
    }

    public function testBadCipherException()
    {
        $key = OpensslKey::create();

        $pass = false;

        try {
            OpensslStatic::encrypt('a secret', $key, 'lol this cipher doesnt exist', 'sha3-256');
        } catch (Exception|ValueError $e) {
            $pass = true;
        }

        $this->assertTrue($pass);
    }

    public function testBadAlgoException()
    {
        $key = OpensslKey::create();

        $pass = false;

        try {
            OpensslStatic::encrypt('a secret', $key, 'aes-256-gcm', 'lol this algo doesnt exist');
        } catch (Exception|ValueError $e) {
            $pass = true;
        }

        $this->assertTrue($pass);
    }

    public function testCrossDecryptFails()
    {
        $key = OpensslKey::create();

        $this->expectException(InvalidChecksumException::class);

        $e = OpensslStatic::encrypt('AAAA', $key, 'aes-256-gcm', 'sha256');
        $d = OpensslStatic::decrypt($e, $key, 'aes-256-ctr', 'sha256');
    }
}
