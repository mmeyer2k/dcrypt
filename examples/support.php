<?php

require __DIR__ . '/../vendor/autoload.php';

foreach (hash_algos() as $algo) {
    foreach (openssl_get_cipher_methods() as $meth) {
        echo str_pad("[$algo]", 20);
        echo str_pad("[$meth]", 40);

        try {
            $e = \Dcrypt\OpensslStatic::encrypt('AAAA', 'BBBB', $meth, $algo);
            $d = \Dcrypt\OpensslStatic::decrypt($e, 'BBBB', $meth, $algo);

            echo " [pass] ";
        } catch (\Exception $e) {
            $m = $e->getMessage();
            echo " [fail] [$m]";
        } catch (\Error $e) {
            $m = $e->getMessage();
            echo " [fail] [$m]";
        } finally {
            echo "\n";
        }
    }
}
