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

class OpensslStack
{
    /**
     * @var array
     */
    private $stack = [];

    /**
     * @var string
     */
    private $passkey;

    /**
     * @var int
     */
    private $cost;

    /**
     * OpensslStack constructor.
     * @param string $passkey
     * @param int $cost
     */
    public function __construct(string $passkey, int $cost = 0)
    {
        $this->passkey = $passkey;

        $this->cost = $cost;

        return $this;
    }

    /**
     * @param string $cipher
     * @param string $algo
     * @return OpensslStack
     */
    public function add(string $cipher, string $algo): self
    {
        $this->stack[] = [$cipher, $algo];
    }

    /**
     * @param string $data
     * @return string
     * @throws \Exception
     */
    public function encrypt(string $data): string
    {
        foreach ($this->stack as $s) {
            $data = OpensslStatic::encrypt($data, $this->passkey, $s[0], $s[1], $this->cost);
        }

        return $data;
    }

    /**
     * @param string $data
     * @return string
     * @throws \Exception
     */
    public function decrypt(string $data): string
    {
        foreach (\array_reverse($this->stack) as $s) {
            $data = OpensslStatic::decrypt($data, $this->passkey, $s[0], $s[1], $this->cost);
        }

        return $data;
    }
}