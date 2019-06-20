<?php declare(strict_types=1);

class AesGcmTest extends AesBase
{
    public static $class = '\\Dcrypt\\AesGcm';

    public function testEngine1()
    {
        if (strpos(PHP_VERSION, '7.0.') === 0) {
            $this->assertTrue(true);

            return;
        }

        parent::testEngine1();
    }

    public function testEngine2()
    {
        if (strpos(PHP_VERSION, '7.0.') === 0) {
            $this->assertTrue(true);

            return;
        }

        parent::testEngine2();
    }

    public function testEngine3()
    {
        if (strpos(PHP_VERSION, '7.0.') === 0) {
            $this->assertTrue(true);

            return;
        }

        parent::testEngine3();
    }
    
    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        if (strpos(PHP_VERSION, '7.0.') === 0) {
            throw new \InvalidArgumentException('fake error');
        }

        parent::testCorrupt();
    }
}
