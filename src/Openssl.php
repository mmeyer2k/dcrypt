<?php

declare(strict_types=1);

namespace Dcrypt;

use Exception;

class Openssl
{
    private $cipher;
    private $algo;
    private $key;

    /**
     * Openssl constructor.
     *
     * @param string $cipher
     * @param string $algo
     * @param string $key
     */
    public function __construct(string $cipher, string $algo, string $key)
    {
        [$this->cipher, $this->algo, $this->key] = func_get_args();
    }

    /**
     * @param string $data
     *
     * @throws Exception
     *
     * @return string
     */
    public function decrypt(string $data): string
    {
        return OpensslStatic::decrypt($data, $this->key, $this->cipher, $this->algo);
    }

    /**
     * @param string $data
     *
     * @throws Exception
     *
     * @return string
     */
    public function encrypt(string $data): string
    {
        return OpensslStatic::encrypt($data, $this->key, $this->cipher, $this->algo);
    }
}
