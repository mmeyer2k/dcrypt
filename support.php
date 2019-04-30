<?php

require __DIR__ . '/vendor/autoload.php';

foreach (hash_algos() as $algo) {
    foreach (openssl_get_cipher_methods() as $meth) {
        // Skip any unsupported ciphers
        if (!\openssl_cipher_iv_length($meth)) {
            continue;
        }

        try {

            #echo str_pad(strlen($e), 10);
            echo str_pad("[$algo]", 20);
            echo str_pad("[$meth]", 40);

            $e = \Dcrypt\OpensslStatic::encrypt('AAAA', 'BBBB', $meth, $algo, 1);
            $d = \Dcrypt\OpensslStatic::decrypt($e, 'BBBB', $meth, $algo);

            echo " [pass] ";
        } catch (\Exception $e) {
            $m = $e->getMessage();
            echo " [fail] [$m]";
            continue;
        } finally {
            echo "\n";
        }
    }
}