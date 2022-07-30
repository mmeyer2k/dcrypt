<?php

declare(strict_types=1);

namespace Dcrypt;

use Exception;

class OpensslStack
{
    private array $_stack = [];
    private string $_key;

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
     * @throws Exception
     *
     * @return string
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
     * @throws Exception
     *
     * @return string
     */
    public function decrypt(string $data): string
    {
        foreach (array_reverse($this->_stack) as $s) {
            $data = OpensslStatic::decrypt($data, $this->_key, $s[0], $s[1]);
        }

        return $data;
    }
}
