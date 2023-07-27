<?php

namespace Eshow\Encryption\bin;

use Eshow\Encryption\exception\PubKeyException;

class Action
{
    private $config;

    /**
     * @throws PubKeyException
     */
    public function __construct($config)
    {
        $this->config = $config;
        $this->config["timestampLimit"] = $config["timestampLimit"] ?: 60;
        if (empty($config["publicKey"])) {
            throw new PubKeyException();
        }
        $this->config["publicKey"] = openssl_pkey_get_public($config["publicKey"]);//获取公钥内容
        if ($this->config["publicKey"] === false) {
            throw new PubKeyException();
        }
    }

    public function __destruct()
    {
        if (phpversion() < "8.0.0") {
            // 关闭公钥资源
            openssl_free_key($this->config["publicKey"]);
        }
    }

    /**
     * 解密
     * @throws PubKeyException
     */
    public function decrypt($decryptData)
    {
        $decryptedData = "";
        // 获取 RSA 解密的最大块大小
        $blockSize = $this->getRSAMaxBlockSize();
        $encryptedBlocks = str_split($decryptData, $blockSize);
        foreach ($encryptedBlocks as $encryptedBlock) {
            $decryptedBlock = "";
            // 解密当前块
            if (openssl_public_decrypt(base64_decode($encryptedBlock), $decryptedBlock, $this->config["publicKey"])) {
                $decryptedData .= $decryptedBlock;
            } else {
                //解密失败
                throw new PubKeyException("Decryption failed", 10002);
            }
        }
        $dataArray = json_decode($decryptedData, true);
        if ($dataArray !== false) {
            $data = $dataArray["data"];
            $timestamp = intval($dataArray["timestamp"]);
            // 验证时间戳的有效性
            $currentTime = time();
            if (abs($currentTime - $timestamp) <= $this->config["timestampLimit"]) {
                // 时间戳有效，可以继续处理数据
                return $data;
            } else {
                // 时间戳无效，数据可能被篡改或过期
                throw new PubKeyException("Invalid timestamp. Data may have been tampered with or expired.", 10004);
            }
        } else {
            //数据格式不正确
            throw new PubKeyException("Invalid data format.", 10003);
        }
    }

    private function getRSAMaxBlockSize()
    {
        // RSA 解密算法每次解密的最大块大小取决于密钥的长度
        // 一般情况下，可以使用如下规则来计算最大块大小：
        // 对于 2048 位的 RSA 密钥，最大块大小为 256 字节
        // 对于 4096 位的 RSA 密钥，最大块大小为 512 字节
        // 具体长度需要根据密钥的长度来确定
        $keyLen = ((int)openssl_pkey_get_details($this->config["publicKey"])['bits']) / 8;
        return 4 * ceil($keyLen / 3);
    }
}