<?php

declare(strict_types=1);

namespace Dcrypt\Tests;

use Dcrypt\Openssl;
use Dcrypt\OpensslKey;
use PHPUnit\Framework\TestCase;

class OpensslTest extends TestCase
{
    public function testOOEncryptor()
    {
        $crypt = new Openssl('aes-256-cbc', 'sha3-256', OpensslKey::create());

        $test1 = $crypt->encrypt(__FUNCTION__);
        $test2 = $crypt->decrypt($test1);

        $this->assertEquals(__FUNCTION__, $test2);
    }
}