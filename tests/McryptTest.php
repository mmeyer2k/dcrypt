<?php

use Dcrypt\Mcrypt;

require __DIR__ . '/../helpers/swaprandbyte.php';

class McryptTest extends PHPUnit_Framework_TestCase
{

    public function testEngine()
    {
        $modes = require __DIR__ . '/../helpers/mcrypt/modes.php';
        $ciphers = require __DIR__ . '/../helpers/mcrypt/ciphers.php';

        foreach (hash_algos() as $algo) {
            $input = 'AAAAAAAA';
            $key = 'AAAAAAAA';
            $cost = 0;

            foreach ($modes as $mode) {
                foreach ($ciphers as $cipher) {
                    $encrypted = Mcrypt::encrypt($input, $key, $cost, $cipher, $mode, $algo);
                    $this->assertEquals($input, Mcrypt::decrypt($encrypted, $key, $cost, $cipher, $mode, $algo));

                    // Perform a validation by replacing a random byte to make sure
                    // the decryption fails. After enough successful runs,
                    // all areas of the cypher text will have been tested
                    // for integrity
                    $corrupt = swaprandbyte($encrypted);
                    $this->assertFalse(Mcrypt::decrypt($corrupt, $key, $cost, $cipher, $mode, $algo));
                }
            }
        }
    }

}
