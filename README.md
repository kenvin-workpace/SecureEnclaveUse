# SecureEnclaveUse
使用Keychain+SE(SecureEnclave)，封装的加解密/签名验签工具

## (枚举)SEStatus
```
FAILED                 // 失败
SUCCESS                // 成功
PARAM_ERROR            // 入参错误
```

## (结构体)SEInfoRef
````
var key:String?     // 加密/解密/签名成功后数据
var status:SEStatus // Block回调
````

## 加密、解密、删除、是否生成过，调用示例
1. 加密
```
SecureEnclaveUtil.shareInstnace.encrypt(str: inputStr.text ?? "") { (info) in
    if info.status != .SUCCESS {
        encryptVerifyStr.text = String(describing: info.status)
        return
    }
    // 加密成功
    encryptVerifyStr.text = info.key
}
```
2. 解密
```
SecureEnclaveUtil.shareInstnace.decrypt(str: encryptVerifyStr.text) { (info) in
    if info.status != .SUCCESS {
        decryptSignStr.text = String(describing: info.status)
        return
    }
    // 解密成功
    decryptSignStr.text = info.key
}
```
3. 删除
```
let result = SecureEnclaveUtil.shareInstnace.isExistKeyPair()
isExistResult.text = String(describing: result)
```
4. 是否生成过
```
let result = SecureEnclaveUtil.shareInstnace.delete()
deleteResult.text = String(describing: result)
```

## 签名、验签、删除、是否生成过，调用示例
1. 签名
```
SecureEnclaveUtil.shareInstnace.sign(str: inputStr.text ?? "") { (info) in
    if info.status != .SUCCESS {
        encryptVerifyStr.text = String(describing: info.status)
        return
    }
    // 签名成功
    encryptVerifyStr.text = info.key
}
```
2. 验签
```
let result = SecureEnclaveUtil.shareInstnace.verify(str: inputStr.text ?? "", signatureStr: encryptVerifyStr.text ?? "")
decryptSignStr.text = String(describing: result)
```
3. 删除
```
let result = SecureEnclaveUtil.shareInstnace.isExistSignKeyPair()
isExistResult.text = String(describing: result)
```
4. 是否生成过
```
let result = SecureEnclaveUtil.shareInstnace.deleteSign()
deleteResult.text = String(describing: result)
```
