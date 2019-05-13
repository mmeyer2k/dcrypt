<?php declare(strict_types=1);

use Dcrypt\Hash;

class HashTest extends \PHPUnit\Framework\TestCase
{
    private static $input = 'AAAAAAAA';
    private static $key = 'BBBBBBBBCCCCCCCC';

    public static $vectors = [
        'u+zL1DMeZeZJ99WiKayy0ciKVJAUetQNoofv/xzCDlhnv+INgGrQ0klVyXSUl8+Yk5zgvZKPNY3nFB8T',
    ];

    public function testBuild1()
    {
        $h = Hash::make('AAAA', 'BBBB', 100);

        $this->assertEquals(60, strlen($h));

        $this->assertTrue(Hash::verify('AAAA', $h, 'BBBB'));
    }

    public function testBuild2()
    {
        $h = Hash::make(self::$input, self::$key);

        $this->assertEquals(60, strlen($h));

        $this->assertTrue(Hash::verify(self::$input, $h, self::$key));
    }

    public function testBuild3()
    {
        $h = Hash::make(self::$input, self::$key, 100);

        $this->assertEquals(60, strlen($h));
    }

    public function testBuildFail1()
    {
        $h = Hash::make('AAAA', 'BBBB', 100);

        $this->assertFalse(Hash::verify('AAAA', $h, 'CCCC'));
    }

    public function testBuildFail2()
    {
        $h = Hash::make(self::$input, self::$key);

        $this->assertFalse(Hash::verify('not the same string', $h, self::$key));
    }

    public function testVectors()
    {
        //echo base64_encode(Hash::make(self::$input, self::$key, 1000));
        foreach (self::$vectors as $vector) {
            $vector = base64_decode($vector);
            $this->assertTrue(Hash::verify(self::$input, $vector, self::$key));
        }
    }
}
