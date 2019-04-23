<?php

use Dcrypt\AesCbc;

class AesCbcTest extends \PHPUnit\Framework\TestCase
{

    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'C/drsZG/o8D2JEvGJFCE3F9opDEEoWiKsNiu6mupqIghorZokTyzn2VNUAbkLIhxX2+QdrwzJuqVQPih/DrAicMXiiY=',
        'iluC2ip9nQZUpS9zdCfQ9OVvLrzx0OBKauv6FMu39tX8mhRCn4/dr3dDVcOJotMrC8xnxJBfOeImtqUGWEDaAS2EBws=',
        'gyrSPnQTTKDiGX98C8MDcxfzB9AMEFFrRX27BUcfWsQbjlkjrVWg9WRsSeOicpkqXXNRV/QIAquWycfszPQh8dOIY48=',
    ];

    public function testEngine1()
    {
        $encrypted = AesCbc::encrypt(self::$input, self::$key, 10000);
        $decrypted = AesCbc::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine2()
    {
        $encrypted = AesCbc::encrypt(self::$input, self::$key);
        $decrypted = AesCbc::decrypt($encrypted, self::$key);

        $this->assertEquals(self::$input, $decrypted);
    }

    public function testEngine3()
    {
        $input = \random_bytes(16);
        $key = \random_bytes(256);

        $encrypted = AesCbc::encrypt($input, $key);
        $decrypted = AesCbc::decrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted);
    }

    public function testVectors()
    {
        foreach (self::$vectors as $vector) {
            #var_dump(base64_encode(AesCbc::encrypt(self::$input, self::$key)));
            $decrypted = AesCbc::decrypt(base64_decode($vector), self::$key);
            $this->assertEquals(self::$input, $decrypted);
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        $encrypted = AesCbc::encrypt(self::$input, self::$key, 10000);
        $this->assertEquals(self::$input, AesCbc::decrypt($encrypted, self::$key));
        AesCbc::decrypt($encrypted . 'A', self::$key);
    }
}
