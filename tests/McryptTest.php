<?php

use Dcrypt\Mcrypt;

class McryptTest extends TestSupport
{

    public function testEngine()
    {
        // If PHP 7.1, skip this test
        if (!function_exists('mcrypt_get_iv_size')) {
            $this->assertTrue(true);
            return;
        }
        
        $modes = self::mcryptModes();
        $ciphers = self::mcryptCiphers();

        foreach (hash_algos() as $algo) {
            $input = 'AAAAAAAA';
            $key = 'AAAAAAAA';
            $cost = 0;

            foreach ($modes as $mode) {
                foreach ($ciphers as $cipher) {
                    $encrypted = Mcrypt::encrypt($input, $key, $cost, $cipher, $mode, $algo);
                    $this->assertEquals($input, Mcrypt::decrypt($encrypted, $key, $cost, $cipher, $mode, $algo));
                }
            }
        }
    }

}
