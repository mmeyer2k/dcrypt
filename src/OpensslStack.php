<?php

declare(strict_types=1);

/**
 * OpensslStack.php.
 *
 * PHP version 7
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 */

namespace Dcrypt;

use Exception;

/**
 * A factory class to build and use custom encryption stacks.
 *
 * @category Dcrypt
 *
 * @author   Michael Meyer (mmeyer2k) <m.meyer2k@gmail.com>
 * @license  http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @link     https://github.com/mmeyer2k/dcrypt
 */
class OpensslStack
{
    /**
     * Stack of cipher/algo combos.
     *
     * @var array
     */
    private $_stack = [];

    /**
     * High entropy key.
     *
     * @var string
     */
    private $_key;

    /**
     * OpensslStack constructor.
     *
     * @param string $key Password or key
     */
    public function __construct(string $key)
    {
        $this->_key = $key;
    }

    /**
     * Add a new cipher/algo combo to the execution stack.
     *
     * @param string $cipher Cipher mode to use
     * @param string $algo   Hashing algo to use
     *
     * @return OpensslStack
     */
    public function add(string $cipher, string $algo): self
    {
        $this->_stack[] = [$cipher, $algo];

        return $this;
    }

    /**
     * Encrypt data using custom stack.
     *
     * @param string $data Data to encrypt
     *
     * @return string
     * @throws Exception
     */
    public function encrypt(string $data): string
    {
        foreach ($this->_stack as $s) {
            $data = OpensslStatic::encrypt($data, $this->_key, $s[0], $s[1]);
        }

        return $data;
    }

    /**
     * Decrypt data using custom stack.
     *
     * @param string $data Data to decrypt
     *
     * @return string
     * @throws Exception
     */
    public function decrypt(string $data): string
    {
        foreach (array_reverse($this->_stack) as $s) {
            $data = OpensslStatic::decrypt($data, $this->_key, $s[0], $s[1]);
        }

        return $data;
    }
}
