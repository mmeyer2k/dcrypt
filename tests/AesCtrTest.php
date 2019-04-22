<?php

use Dcrypt\AesCtr;

class AesCtrTest extends TestSupport
{

    private static $input = 'AAAAAAAA';
    private static $key = 'AAAAAAAA';

    public static $vectors = [
        'eUik7Y+Tue+i7hmc6fRaOi2YY/mk9Zw1yapHZ6Qx8sESIZHMj403NNdXZ/8DPUsZytdVytFA0lfhX48V',
        '65i8H/N18gOv9F98rFgH7BorCYKRRbg0ObDCVMdKEpI16SSjrvrV/sEvXL8bzqzXACh6kI1RyCqOqp7w',
        'vhDDnto9FFNKvThtI6AMNl/TLKoH02fKssMVNptiUJuYi/523qpWCTwQ3BHYwr5wmzlDl9rcSx7BQfOd',
    ];

    public function testEngine1()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key, 10000);
        $decrypted = AesCtr::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine2()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key);
        $decrypted = AesCtr::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine3()
    {
        $input = \random_bytes(16);
        $key = \random_bytes(256);

        $encrypted = AesCtr::encrypt($input, $key);
        $decrypted = AesCtr::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testVectors()
    {
        foreach (self::$vectors as $vector) {
            #var_dump(base64_encode(AesCtr::encrypt(self::$input, self::$key)));
            $decrypted = AesCtr::decrypt(base64_decode($vector), self::$key);
            $this->assertEquals(self::$input, $decrypted);
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $encrypted = AesCtr::encrypt(self::$input, self::$key, 10000);
        $this->assertEquals(self::$input, AesCtr::decrypt($encrypted, self::$key));

        $corrupt = self::swaprandbyte($encrypted);
        AesCtr::decrypt($corrupt, self::$key);
    }
}
