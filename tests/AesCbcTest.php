<?php

use Dcrypt\AesCbc;

class AesCbcTest extends TestSupport
{

    private static $input = 'AAAAAAAA';
    private static $key = 'AAAAAAAA';

    public static $vectors = [
        '2MMJ9lAL6xdtyR8ZZeXEWR2nmzF7lzsgoSoGhSuO3dQ0nZjDwur4ade9kZCziJTOzbefdbuDCgrKhVqg1rgy844bJhk=',
        'iXK0MZVImebouYol8FUXFmwr2VUAvx3AE7aAc6eWsCHbx5Okt3IeTlnAwYjbY8T/scxZYf0geIVZsyEaRIapHtbBu1E=',
        'cgZygH85el9GcUSpD7ltADtI3aByO/uqIzKQD4mpxQWiHZkTopSVQIG0DdeDLtycib91LhtemLzLolH9SWKRoe19kro=',
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

        $corrupt = self::swaprandbyte($encrypted);
        AesCbc::decrypt($corrupt, self::$key);
    }
}
