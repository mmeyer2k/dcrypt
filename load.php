<?php

/**
 * load.php
 * 
 * This file performs class loading operations if/when composer is not available.
 * Including this file in your project will give you immediate access to the 
 * functionality of Dcrypt.
 * 
 * PHP version 5
 * 
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
$g = 'dcrypt_loaded';

if (!defined($g)) {
    define($g, true);
    
    $files = array(
        'Aes',
        'Cryptobase',
        'Hash',
        'Mcrypt',
        'Openssl',
        'Otp',
        'Pkcs7',
        'Random',
        'Rc4',
        'Spritz',
        'Strcmp',
    );

    foreach ($files as $f) {
        require_once __DIR__ . "/src/$f.php";
    }
}
