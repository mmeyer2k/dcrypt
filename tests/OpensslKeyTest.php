<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyException;
use Dcrypt\OpensslKey;

class OpensslKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testNewKeyTooShort()
    {
        \Dcrypt\OpensslKey::create(32);

        $this->expectException(InvalidKeyException::class);

        \Dcrypt\OpensslKey::create(31);
    }

    public function testKeyInvalidBase64()
    {
        $str = str_repeat('A', 32);

        $this->expectException(InvalidKeyException::class);

        new OpensslKey('sha3-256', $str);
    }
}
