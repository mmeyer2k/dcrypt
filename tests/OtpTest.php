<?php declare(strict_types=1);

use Dcrypt\Otp;

class OtpTest extends \PHPUnit\Framework\TestCase
{
    public function testCrypt()
    {
        foreach (range(1, 1000, 100) as $mult) {
            $input = str_repeat('A', 4 * $mult);
            $key = \random_bytes(32);

            /*
             * Test encryption
             */
            $encrypted = Otp::crypt($input, $key, 1000);
            $this->assertEquals(strlen($input), strlen($encrypted));
            $this->assertNotEquals($input, $encrypted);

            /*
             * Test decryption
             */
            $decrypted = Otp::crypt($encrypted, $key, 1000);
            $this->assertEquals($input, $decrypted);
        }
    }

    public function testVector()
    {
        $json = json_decode(file_get_contents(__DIR__ . '/vectors/otp.json'));

        foreach ($json as $mult => $data) {
            $data = base64_decode($data);
            $expected = str_repeat('A', (int)$mult);
            $this->assertEquals($expected, Otp::crypt($data, 'password', 1000));
        }
    }
}
