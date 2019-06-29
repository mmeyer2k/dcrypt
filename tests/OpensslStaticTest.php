<?php declare(strict_types=1);

class OpensslStaticTest extends \PHPUnit\Framework\TestCase
{
    public function testVectorsAlgos()
    {
        $json = file_get_contents(__DIR__ . '/vectors/openssl-static-algos.json');

        $json = json_decode($json);

        foreach ($json as $algo => $data) {
            try {
                $plaintext = \Dcrypt\OpensslStatic::decrypt(base64_decode($data), 'world', 'aes-256-gcm', $algo, 1000);
            } catch (\Exception|\Error $e) {
                throw new \Exception("Failure in [$algo]: " . $e->getMessage());
            }

            $this->assertEquals('hello', $plaintext);
        }
    }

    public function testVectorsCiphers()
    {
        $json = file_get_contents(__DIR__ . '/vectors/openssl-static-ciphers.json');

        $json = json_decode($json);

        foreach ($json as $cipher => $data) {
            try {
                $plaintext = \Dcrypt\OpensslStatic::decrypt(base64_decode($data), 'world', $cipher, 'sha256', 1000);
            } catch (\Exception|\Error $e) {
                throw new \Exception("Failure in [$cipher]: " . $e->getMessage());
            }

            $this->assertEquals('hello', $plaintext);
        }
    }
}