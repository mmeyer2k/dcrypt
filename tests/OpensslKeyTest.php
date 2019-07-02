<?php declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyException;

class OpensslKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testNewKeyTooShort()
    {
        \Dcrypt\OpensslKey::create(256);

        $this->expectException(InvalidKeyException::class);

        \Dcrypt\OpensslKey::create(128);
    }
}
