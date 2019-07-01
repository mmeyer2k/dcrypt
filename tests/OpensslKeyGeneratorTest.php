<?php declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Exceptions\InvalidKeyException;

class OpensslKeyGeneratorTest extends \PHPUnit\Framework\TestCase
{
    public function testNewKeyTooShort()
    {
        \Dcrypt\OpensslKeyGenerator::newKey(256);

        $this->expectException(InvalidKeyException::class);

        \Dcrypt\OpensslKeyGenerator::newKey(128);
    }
}
