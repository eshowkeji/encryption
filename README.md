# Eshow Encryption
解密sdk
## 安装

```
composer require eshow/encryption
```

## 使用

```
use Eshow\Encryption\bin\Action;
use Eshow\Encryption\exception\PubKeyException;

$decryptData = ""; //需要解密的数据
$config = [
    "timestampLimit"=>60,//超时时间
    "publicKey"=>""//公钥
];
try {

    $action = new Action($config);
    $data = $action->decrypt($decryptData);
}catch (PubKeyException $exception){

}
```

## 异常
| code  | message                          |
| ----- | -------------------------------- |
| 10004 | 时间戳无效，数据可能被篡改或过期 |
| 10003 | 数据格式不正确                   |
| 10002 | 解密失败                         |
| 10001 | 非法密钥                         |
