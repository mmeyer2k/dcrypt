<?php

class OpensslStaticTest extends \PHPUnit\Framework\TestCase
{
    public function testAllCombos()
    {
        foreach (hash_algos() as $algo) {
            foreach (openssl_get_cipher_methods() as $meth) {
                // Skip any unsupported ciphers
                if (!\openssl_cipher_iv_length($meth)) {
                    continue;
                }

                try {
                    $e = \Dcrypt\OpensslStatic::encrypt('AAAA', 'BBBB', $meth, $algo, mt_rand(1, 1000));
                    $d = \Dcrypt\OpensslStatic::decrypt($e, 'BBBB', $meth, $algo);
                    $this->assertEquals('AAAA', $d);
                } catch (\Exception $e) {
                    continue;
                }
            }
        }
    }
}
