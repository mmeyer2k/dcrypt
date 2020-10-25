<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyEncodingException;
use Dcrypt\Exceptions\InvalidKeyLengthException;
use Dcrypt\Exceptions\InvalidPropertyAccessException;
use Dcrypt\OpensslKey;

class OpensslKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testNewKeyTooShort()
    {
        // A key with 32 chars should work...
        \Dcrypt\OpensslKey::create(32);

        $this->expectException(InvalidKeyLengthException::class);

        // but 31 should not.
        \Dcrypt\OpensslKey::create(31);
    }

    public function testKeyInvalidBase64()
    {
        $str = str_repeat('.', 32);

        $this->expectException(InvalidKeyEncodingException::class);

        new OpensslKey('sha3-256', $str);
    }
}
