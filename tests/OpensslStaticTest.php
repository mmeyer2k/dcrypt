<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InternalOperationException;
use Dcrypt\Exceptions\InvalidChecksumException;
use Dcrypt\OpensslKey;
use Dcrypt\OpensslStatic;
use Exception;
use PHPUnit\Framework\TestCase;

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

        // Skip the ciphers that are treated differently by PHP 8.1
        $skip81 = [
            'aes-256-ccm',
            'aes-256-cbc-hmac-sha1',
            'aes-256-cbc-hmac-sha256',
            'aes-128-ccm',
            'aes-128-cbc-hmac-sha1',
            'aes-128-cbc-hmac-sha256',
        ];

        foreach ($json->ciphers as $cipher => $ciphertext) {
            if (version_compare(PHP_VERSION, '8.1.0') >= 0 && in_array($cipher, $skip81)) {
                continue;
            }

            try {
                $plaintext = OpensslStatic::decrypt(base64_decode($ciphertext), $json->key, $cipher, 'sha3-256');
            } catch (\Exception $e) {
            }

            $this->assertEquals('a secret', $plaintext);
        }
    }

    public function testBadCipherException()
    {
        $key = OpensslKey::create();

        $this->expectException(InternalOperationException::class);

        OpensslStatic::encrypt('a secret', $key, 'lol this cipher doesnt exist', 'sha3-256');
    }

    public function testBadAlgoException()
    {
        $key = OpensslKey::create();

        $this->expectException(InternalOperationException::class);

        OpensslStatic::encrypt('a secret', $key, 'aes-256-gcm', 'lol this algo doesnt exist');
    }

    public function testCrossDecryptFails()
    {
        $key = OpensslKey::create();

        $this->expectException(InvalidChecksumException::class);

        $e = OpensslStatic::encrypt('AAAA', $key, 'aes-256-gcm', 'sha256');
        $d = OpensslStatic::decrypt($e, $key, 'aes-256-ctr', 'sha256');
    }
}
