<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyEncodingException;
use Dcrypt\Exceptions\InvalidKeyLengthException;
use Dcrypt\OpensslKey;
use PHPUnit\Framework\TestCase;

class OpensslKeyTest extends TestCase
{
    public function testNewKeyTooShort()
    {
        // A key with 32 chars should work...
        OpensslKey::create(32);

        $this->expectException(InvalidKeyLengthException::class);

        // but 31 should not.
        OpensslKey::create(31);
    }

    public function testKeyInvalidBase64()
    {
        $str = str_repeat('.', 32);

        $this->expectException(InvalidKeyEncodingException::class);

        new OpensslKey('sha3-256', $str);
    }
}
