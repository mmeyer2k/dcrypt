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

        foreach (\hash_algos() as $algo) {
            try {
                OpensslStatic::encrypt('test', 'test', 'aes-256-gcm', $algo, 1);
                $algos[] = $algo;
            } catch(\Error|\Exception $e) {

            }
        }

        return $algos;
    }

    public static function ciphers(): array
    {
        $ciphers = [];

        foreach (\openssl_get_cipher_methods() as $cipher) {
            try {
                OpensslStatic::encrypt('test', 'test', $cipher, 'sha256', 1);
                $ciphers[] = $cipher;
            } catch(\Error|\Exception $e) {

            }
        }

        return $ciphers;
    }
}