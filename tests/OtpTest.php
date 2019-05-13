<?php declare(strict_types=1);

use Dcrypt\Otp;

class OtpTest extends \PHPUnit\Framework\TestCase
{
    public function testCrypt()
    {
        foreach (range(1, 1000, 100) as $mult) {
            $input = str_repeat('A', 4 * $mult);
            $key = openssl_random_pseudo_bytes(32);

            /*
             * Test encryption
             */
            $encrypted = Otp::crypt($input, $key);
            $this->assertEquals(strlen($input), strlen($encrypted));
            $this->assertNotEquals($input, $encrypted);

            /*
             * Test decryption
             */
            $decrypted = Otp::crypt($encrypted, $key);
            $this->assertEquals($input, $decrypted);
        }
    }

    public function testVector()
    {
        $input = 'hello world';
        $pass = 'password';
        $vector = base64_decode('Cf6ULwbiZEbJr1w=');

        $this->assertEquals($input, Otp::crypt($vector, $pass));
    }
}
