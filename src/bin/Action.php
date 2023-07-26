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
        $this->config["timestampLimit"] = $config["timestampLimit"] ?:60;
        if(empty($config["publicKey"])){
            throw new PubKeyException();
        }
        $this->config["publicKey"] = openssl_pkey_get_public($config["publicKey"]);//获取公钥内容
        if($this->config["publicKey"] === false){
            throw new PubKeyException();
        }
    }

    public function __destruct()
    {
        if(phpversion()<"8.0.0"){
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
        if (openssl_public_decrypt(base64_decode($decryptData), $decryptedData, $this->config["publicKey"])) {
            // 解密成功，拆分数据与时间戳
            $dataArray = json_decode($decryptedData,true);
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
                    throw new PubKeyException("Invalid timestamp. Data may have been tampered with or expired.",10004);
                }
            } else {
                //数据格式不正确
                throw new PubKeyException("Invalid data format.",10003);
            }
        } else {
            //解密失败
            throw new PubKeyException("Decryption failed",10002);
        }
    }
}