<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\OpensslStatic;

class OpensslStaticTest extends \PHPUnit\Framework\TestCase
{
    public function testVectorsAlgos()
    {
        $json = file_get_contents(__DIR__ . '/.vectors.json');

        $json = json_decode($json);

        foreach ($json->algos as $algo => $data) {
            try {
                $plaintext = \Dcrypt\OpensslStatic::decrypt(base64_decode($data), $json->key, 'aes-256-gcm', $algo);
            } catch (\Exception | \Error $e) {
                throw new \Exception("Failure in [$algo]: " . $e->getMessage());
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
                $plaintext = \Dcrypt\OpensslStatic::decrypt(base64_decode($data), $json->key, $cipher, 'sha3-256');
            } catch (\Exception | \Error $e) {

            }

            $this->assertEquals('a secret', $plaintext);
        }
    }

    public function testBadCipherException()
    {
        $key = \Dcrypt\OpensslKey::create();

        $pass = false;

        try {
            OpensslStatic::encrypt('a secret', $key, 'lol this cipher doesnt exist', 'sha3-256');
        } catch (\Exception $e) {
            $pass = true;
        }

        $this->assertTrue($pass);
    }

    public function testBadAlgoException()
    {
        $key = \Dcrypt\OpensslKey::create();

        $pass = false;

        try {
            OpensslStatic::encrypt('a secret', $key, 'aes-256-gcm', 'lol this algo doesnt exist');
        } catch (\Exception $e) {
            $pass = true;
        }

        $this->assertTrue($pass);
    }

    public function testCrossDecryptFails()
    {
        $key = \Dcrypt\OpensslKey::create();

        $this->expectException(\Dcrypt\Exceptions\InvalidChecksumException::class);

        $e = \Dcrypt\OpensslStatic::encrypt('AAAA', $key, 'aes-256-gcm', 'sha256');
        $d = \Dcrypt\OpensslStatic::decrypt($e, $key, 'aes-256-ctr', 'sha256');
    }
}
