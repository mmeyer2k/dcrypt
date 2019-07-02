<?php declare(strict_types=1);

/**
 * OpensslSupported.php
 *
 * PHP version 7
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt;

final class OpensslSupported
{
    /**
     * Returns all hash algos supported by OpenSSL as an array of strings.
     *
     * @return array
     */
    public static function algos(): array
    {
        $algos = [];

        $key = \Dcrypt\OpensslKey::create();

        foreach (\hash_algos() as $algo) {
            try {
                $a = OpensslStatic::encrypt('test', $key, 'aes-256-gcm', $algo);
                $b = OpensslStatic::decrypt($a, $key, 'aes-256-gcm', $algo);

                if ($b === 'test') {
                    $algos[] = $algo;
                }
            } catch(\Error|\Exception $e) {

            }
        }

        return $algos;
    }

    public static function ciphers(): array
    {
        $ciphers = [];

        $key = \Dcrypt\OpensslKey::create();

        foreach (\openssl_get_cipher_methods() as $cipher) {
            try {
                $a = OpensslStatic::encrypt('test', $key, $cipher, 'sha256');
                $b = OpensslStatic::decrypt($a, $key, $cipher, 'sha256');

                if ($b === 'test') {
                    $ciphers[] = $cipher;
                }
            } catch(\Error|\Exception $e) {

            }
        }

        return $ciphers;
    }
}