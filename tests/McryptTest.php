<?php

use Dcrypt\Mcrypt;

require __DIR__ . '/../helpers/swaprandbyte.php';

class McryptTest extends PHPUnit_Framework_TestCase
{

    public function testMismatch()
    {
        $i = 'abc';
        $k = '123';

        // Test for mode mismatch detection

        $e = Mcrypt::encrypt($i, $k, MCRYPT_MODE_CBC);
        $this->assertFalse(Mcrypt::decrypt($i, $k, MCRYPT_MODE_OFB));

        // Test for cipher mismatch detection
        $e = Mcrypt::encrypt($i, $k, MCRYPT_MODE_CBC, MCRYPT_TWOFISH);
        $this->assertFalse(Mcrypt::decrypt($i, $k, MCRYPT_MODE_CBC, MCRYPT_SERPENT));

        // Test for both mismatch detection ;=)
        $e = Mcrypt::encrypt($i, $k, MCRYPT_MODE_ECB, MCRYPT_TWOFISH);
        $this->assertFalse(Mcrypt::decrypt($i, $k, MCRYPT_MODE_CBC, MCRYPT_SERPENT));

        // Test for algo mismatch detection
        $e = Mcrypt::encrypt($i, $k, MCRYPT_MODE_CBC, MCRYPT_TWOFISH, 'sha512');
        $this->assertFalse(Mcrypt::decrypt($i, $k, MCRYPT_MODE_CBC, MCRYPT_TWOFISH, 'sha256'));
    }

    public function testEngine()
    {
        $modes = require __DIR__ . '/../helpers/mcrypt/modes.php';
        $ciphers = require __DIR__ . '/../helpers/mcrypt/ciphers.php';

        foreach (hash_algos() as $algo) {
            $input = 'AAAAAAAA';
            $key = 'AAAAAAAA';

            foreach ($modes as $mode) {
                foreach ($ciphers as $cipher) {
                    $encrypted = Mcrypt::encrypt($input, $key, $mode, $cipher, $algo);
                    $this->assertEquals($input, Mcrypt::decrypt($encrypted, $key, $mode, $cipher, $algo));

                    // Perform a validation by replacing a random byte to make sure
                    // the decryption fails. After enough successful runs,
                    // all areas of the cypher text will have been tested
                    // for integrity
                    $corrupt = swaprandbyte($encrypted);
                    $this->assertFalse(Mcrypt::decrypt($corrupt, $key, $mode, $cipher, $algo));
                }
            }
        }
    }

}
