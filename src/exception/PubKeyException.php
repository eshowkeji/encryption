<?php

namespace Eshow\Encryption\exception;

/**
 * 解密异常
 */
class PubKeyException extends \Exception
{
    public function __construct($message = "", $code = 10001, Throwable $previous = null)
    {
        $message = "pub key invalid";
        parent::__construct($message, $code, $previous);
    }
}