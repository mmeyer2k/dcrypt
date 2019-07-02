<?php declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyException;
use Dcrypt\OpensslKey;

class OpensslKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testNewKeyTooShort()
    {
        \Dcrypt\OpensslKey::create(2048);

        $this->expectException(InvalidKeyException::class);

        \Dcrypt\OpensslKey::create(2047);
    }

    public function testDetectDoubleEncodedKey()
    {
        $key = \Dcrypt\OpensslKey::create();

        // Double encode the key
        $key = \base64_encode($key);

        $this->expectException(InvalidKeyException::class);

        $key = new OpensslKey('sha3-256', $key, '');
    }
}
