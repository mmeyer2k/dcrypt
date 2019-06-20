<?php declare(strict_types=1);

class OpensslStaticTest extends \PHPUnit\Framework\TestCase
{
    public function testVectorsFile()
    {
        $json = file_get_contents(__DIR__ . '/vectors.txt');

        $json = json_decode($json);

        foreach ($json as $cipher => $algos) {
            foreach ($algos as $algo => $data) {
                try {
                    $plaintext = \Dcrypt\OpensslStatic::decrypt(base64_decode($data), 'world', $cipher, $algo, 10);
                } catch (\Exception $e) {
                    throw new \Exception("Failure in [$cipher/$algo]:" . $e->getMessage());
                }
                $this->assertEquals('hello', $plaintext);
            }
        }
    }
}