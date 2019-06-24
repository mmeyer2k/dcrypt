<?php declare(strict_types=1);

/**
 * OpensslKeyGenerator.php
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

final class OpensslKeyGenerator
{
    private $hash;
    private $algo;
    private $ivr;

    /**
     * OpensslKeyGenerator constructor.
     *
     * @param string $algo
     * @param string $pass
     * @param string $cipher
     * @param string $ivr
     * @param int $cost
     */
    public function __construct(string $algo, string $pass, string $cipher, string $ivr, int $cost)
    {
        //
        $this->hash = \hash_pbkdf2($algo, ($pass . $cipher), $ivr, $cost, 0, true);

        //
        $this->algo = $algo;

        //
        $this->ivr = $ivr;
    }

    /**
     * @return string
     */
    public function authenticationKey(): string
    {
        return $this->deriveKey(__FUNCTION__);
    }

    /**
     * @return string
     */
    public function encryptionKey(): string
    {
        return $this->deriveKey(__FUNCTION__);
    }

    private function deriveKey(string $authinfo): string
    {
        $key = \hash_hkdf($this->algo, $this->hash, 0, $authinfo, $this->ivr);

        if ($key === false) {
            throw new \Exception("Hash algo $this->algo is not supported");
        }

        return $key;
    }
}