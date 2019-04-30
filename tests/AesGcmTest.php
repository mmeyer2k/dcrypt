<?php

class AesGcmTest extends AesBase
{
    public static $vectors = [
        'SQcblZF/dfwt1ElG7cvYftDYXfnswZRw15QhekJ/PkmMwdiukBJQ9vyOoR83kNlgCPYH4LN/gbMgkH4j',
    ];

    public static $class = '\\Dcrypt\\AesGcm';

    /**
     * @expectedException
     */
    public function testEngine1()
    {
        parent::testEngine1();
    }

    /**
     * @expectedException
     */
    public function testEngine2()
    {
        parent::testEngine2();
    }
}
