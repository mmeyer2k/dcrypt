<?php

include 'vendor/autoload.php';
echo PHP_EOL;
$o = \Dcrypt\Otp::crypt('hello world', 'password');
var_dump(base64_encode($o));
echo PHP_EOL;
echo PHP_EOL;