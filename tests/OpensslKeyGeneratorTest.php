<?php declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyException;

class OpensslKeyGeneratorTest extends \PHPUnit\Framework\TestCase
{
    public function testNewKeyTooShort()
    {
        \Dcrypt\OpensslKey::newKey(256);

        $this->expectException(InvalidKeyException::class);

        \Dcrypt\OpensslKey::newKey(128);
    }
}
