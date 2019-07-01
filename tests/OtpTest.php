<?php declare(strict_types=1);

use Dcrypt\Otp;

class OtpTest extends \PHPUnit\Framework\TestCase
{
    public function testCrypt()
    {
        $key = \Dcrypt\OpensslKeyGenerator::newKey();

        foreach (range(1, 1000, 100) as $mult) {
            $input = str_repeat('A', 4 * $mult);

            $encrypted = Otp::crypt($input, $key);

            $this->assertEquals(strlen($input), strlen($encrypted));
            $this->assertNotEquals($input, $encrypted);

            $decrypted = Otp::crypt($encrypted, $key);
            $this->assertEquals($input, $decrypted);
        }
    }

    public function testVector()
    {
        $json = json_decode(file_get_contents(__DIR__ . '/vectors/otp.json'));
        $key = file_get_contents(__DIR__ . '/vectors/.testkey');

        foreach ($json as $mult => $data) {
            $data = base64_decode($data);
            $expected = str_repeat('A', (int)$mult);
            $this->assertEquals($expected, Otp::crypt($data, $key));
        }
    }
}
