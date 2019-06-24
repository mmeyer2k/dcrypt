<?php declare(strict_types=1);

/**
 * Aes256Ecb.php
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

/**
 * Symmetric AES-256-ECB encryption functions powered by OpenSSL.
 *
 * @category Dcrypt
 * @package  Dcrypt
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class Aes256Ecb extends Aes256Gcm
{
    /**
     * AES-256 cipher identifier that will be passed to openssl
     *
     * @var string
     */
    const CIPHER = 'aes-256-ecb';
}