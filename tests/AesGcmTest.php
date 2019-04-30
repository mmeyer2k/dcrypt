<?php

class AesGcmTest extends AesBase
{
    public static $vectors = [
        'SQcblZF/dfwt1ElG7cvYftDYXfnswZRw15QhekJ/PkmMwdiukBJQ9vyOoR83kNlgCPYH4LN/gbMgkH4j',
    ];

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

    public function testVectors()
    {
        if (strpos(PHP_VERSION, '7.0.') === 0) {
            $this->assertTrue(true);

            return;
        }

        parent::testVectors();
    }
    
    /**
     * @expectedException InvalidArgumentException
     */
    public function testCorrupt()
    {
        if (strpos(PHP_VERSION, '7.0.') === 0) {
            $this->assertTrue(true);

            return;
        }

        parent::testCorrupt();
    }
}
