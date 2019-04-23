<?php

use Dcrypt\AesCtr;

class AesCtrTest extends \PHPUnit\Framework\TestCase
{
    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'lar3oIJLYum+T38ap2CVEMvexQWEp3MFQ4MgiD7DcCi2uR1Up25M/4egtZ8G+gT0LYHR6BQ3QZyl915r',
        'qiE1YpFpQxQvS0nb2OCnQUCn01CzzdgtSKWTgg7TT1sBvxKsTpF1Cjp8RITRda/9FmWUX5F8N5ToIHDq',
        'XSLMlzlJo3WpFy4qxtsMYrGDy7IBMUJNbRXjxaz1IXzMhO/2P4Pa/C1qp5A6ZRl5NscxxL/5jK1sBsGH',
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
        $encrypted = AesCtr::encrypt(self::$input, self::$key, 1);
        $this->assertEquals(self::$input, AesCtr::decrypt($encrypted, self::$key));
        AesCtr::decrypt($encrypted . 'A', self::$key);
    }
}
