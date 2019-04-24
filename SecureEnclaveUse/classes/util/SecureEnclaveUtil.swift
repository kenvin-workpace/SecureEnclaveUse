//
//  SecureEnclaveUtil.swift
//  SecureEnclaveUse
//
//  Created by Kevin on 2019/4/19.
//  Copyright © 2019 Kevin. All rights reserved.
//

import UIKit

private let kSecMessECCKeySize = 256
typealias complete = (_ ref:SEInfoRef) -> Void

class SecureEnclaveUtil {
    
    // 单例
    static let shareInstnace = SecureEnclaveUtil()
    
    // 加密/解密公私钥
    private var kEccPrivateKey,kEccPublicKey:SecKey?
    private var kSecMessECCLabel = "com.hongzhenw.ecc.label"
    
    // 签名/验签公私钥
    private var kEccPrivateSignKey,kEccPublicSignKey:SecKey?
    private var kSecMessECCSignLabel = "dcom.hongzhenw.eccsign.label"
}

// MARK: - 签名/验签/删除/是否已生成
extension SecureEnclaveUtil {
    
    // 签名
    func sign(str:String,complete:complete) -> Void {
        if str.isEmpty {
            print("error: sign str is nil")
            complete(SEInfoRef(statusIn: .PARAM_ERROR, keyIn: nil))
            return
        }
        // 转为二进流
        guard let strData = str.data(using: .utf8) else {
            print("error: param str to data is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 获取公钥
        if getSignKeyPair() == nil {
            print("error: publickey is nil")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        guard let signData = SecKeyCreateSignature(querySignPrivateKey()!, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, strData as CFData, nil) else {
            print("error: sign data is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        let signedData = signData as Data
        let signedDataBase64Str = signedData.base64EncodedString()
        complete(SEInfoRef(statusIn: .SUCCESS, keyIn: signedDataBase64Str))
    }
    
    // 验签
    func verify(str:String,signatureStr:String) -> Bool {
        if str.isEmpty{
            print("error: decrypt str is nil")
            return false
        }
        // 是否生成过
        if !isExistSignKeyPair() {
            print("error: please generate keypair")
            return false
        }
        // 获取公钥
        guard let publicSignKey = getSignKeyPair() else {
            print("error: publickey is nil")
            return false
        }
        guard let publicKeyData = Data(base64Encoded: publicSignKey) else {
            print("error: base64 decode is failed")
            return false
        }
        let publicKeyParams = NSMutableDictionary()
        publicKeyParams.setValue(kSecAttrKeyClassPublic, forKey: kSecAttrKeyClass as String)
        publicKeyParams.setValue(kSecMessECCKeySize, forKey: kSecAttrKeySizeInBits as String)
        publicKeyParams.setValue(kSecAttrKeyTypeECSECPrimeRandom, forKey: kSecAttrKeyType as String)
        // 还原公钥
        guard let publicKey = SecKeyCreateWithData(publicKeyData as CFData, publicKeyParams, nil) else {
            print("error: create pubickey is failed")
            return false
        }
        // 签名数据
        guard let signatureData = Data(base64Encoded: signatureStr) else {
            print("error: sign data is failed")
            return false
        }
        // 待验证数据
        guard let strData = str.data(using: .utf8) else {
            print("error: str to data is failed")
            return false
        }
        // 验签结果
        let verify = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, strData as CFData, signatureData as CFData, nil)
        return verify
    }
    
    // 是否存在
    func isExistSignKeyPair() -> Bool {
        if querySignPrivateKey() == nil {
            return false
        }
        return true
    }
    
    // 删除密钥对
    func deleteSign() -> Bool {
        let dict = NSMutableDictionary()
        dict.setValue(true, forKey: kSecReturnRef as String)
        dict.setValue(kSecClassKey, forKey: kSecClass as String)
        dict.setValue(kSecMessECCSignLabel, forKey: kSecAttrLabel as String)
        dict.setValue(kSecAttrTokenIDSecureEnclave, forKey: kSecAttrTokenID as String)
        
        let status = SecItemDelete(dict)
        if  status != noErr {
            return false
        }
        return true
    }
    
    private func getSignKeyPair() -> String? {
        // 是否生成过
        if let (tempPrivateKey,tempPublicKey) = querySignKeyPair() {
            kEccPublicSignKey = tempPublicKey
            kEccPrivateSignKey = tempPrivateKey
            
            let externalKey = SecKeyCopyExternalRepresentation(tempPublicKey, nil)
            let externalKeyData = externalKey! as Data
            let externalKeyBase64Str = externalKeyData.base64EncodedString()
            return externalKeyBase64Str
        }
        guard let alcObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage], nil) else {
            print("error:alc object is nil")
            return nil
        }
        // 私钥参数
        let privateKeyParams = NSMutableDictionary()
        privateKeyParams.setValue(true, forKey: kSecAttrIsPermanent as String)
        privateKeyParams.setValue(alcObject, forKey: kSecAttrAccessControl as String)
        // 全局参数
        let parameters = NSMutableDictionary()
        parameters.setValue(kSecMessECCSignLabel, forKey: kSecAttrLabel as String)
        parameters.setValue(privateKeyParams, forKey: kSecPrivateKeyAttrs as String)
        parameters.setValue(kSecMessECCKeySize, forKey: kSecAttrKeySizeInBits as String)
        parameters.setValue(kSecAttrTokenIDSecureEnclave, forKey: kSecAttrTokenID as String)
        parameters.setValue(kSecAttrKeyTypeECSECPrimeRandom, forKey: kSecAttrKeyType as String)
        // 生成公私钥
        guard let eccPrivateKey = SecKeyCreateRandomKey(parameters, nil) else {
            print("error: create privatekey is filed")
            return nil
        }
        // 获取公钥
        guard let eccPublicKey = SecKeyCopyPublicKey(eccPrivateKey) else {
            print("error: create publickey is filed")
            return nil
        }
        // 分享公钥
        let externalKey = SecKeyCopyExternalRepresentation(eccPublicKey, nil)
        let externalKeyData = externalKey! as Data
        let externalKeyBase64Str = externalKeyData.base64EncodedString()
        // 变量属性
        kEccPublicSignKey = eccPublicKey
        kEccPrivateSignKey = eccPublicKey
        return externalKeyBase64Str
    }
    
    // 获取公私钥
    private func querySignKeyPair() -> (SecKey,SecKey)? {
        guard let eccPrivateKey = querySignPrivateKey() else {
            print("error: get privateSingKey is failed")
            return nil
        }
        guard let eccPublicKey = SecKeyCopyPublicKey(eccPrivateKey) else {
            print("error: get publicSingKey is failed")
            return nil
        }
        return (eccPrivateKey,eccPublicKey)
    }
    // 获取私钥
    private func querySignPrivateKey() -> SecKey?{
        let dict = NSMutableDictionary()
        dict.setValue(true, forKey: kSecReturnRef as String)
        dict.setValue(kSecClassKey, forKey: kSecClass as String)
        dict.setValue(kSecMessECCSignLabel, forKey: kSecAttrLabel as String)
        dict.setValue(kSecMessECCKeySize, forKey: kSecAttrKeySizeInBits as String)
        dict.setValue(kSecAttrKeyTypeECSECPrimeRandom, forKey: kSecAttrKeyType as String)
        
        var eccPrivateKey:CFTypeRef?
        let status = SecItemCopyMatching(dict, &eccPrivateKey)
        if status != noErr {
            return nil
        }
        return (eccPrivateKey as! SecKey)
    }
}

// MARK: - 加密/解密/删除/是否已生成
extension SecureEnclaveUtil {
    
    // 加密
    func encrypt(str:String,complete:complete) -> Void {
        if str.isEmpty {
            print("error: encrypt str is nil")
            complete(SEInfoRef(statusIn: .PARAM_ERROR, keyIn: nil))
            return
        }
        // 获取公钥
        guard let key = getKeyPair() else {
            print("error: publickey is nil")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 公钥Data
        let publicKeyData = Data(base64Encoded: key)
        // 公钥材料
        let publicKeyParams = NSMutableDictionary()
        publicKeyParams.setValue(kSecMessECCKeySize, forKey: kSecAttrKeySizeInBits as String)
        publicKeyParams.setValue(kSecAttrKeyClassPublic, forKey: kSecAttrKeyClass as String)
        publicKeyParams.setValue(kSecAttrKeyTypeECSECPrimeRandom, forKey: kSecAttrKeyType as String)
        // 还原公钥
        guard let publicKey = SecKeyCreateWithData(publicKeyData! as CFData, publicKeyParams, nil) else {
            print("error: create publickey is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 待加密数据
        guard let strData = str.data(using: .utf8) else {
            print("error: param str to data is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 公钥加密数据
        guard let encryptData = SecKeyCreateEncryptedData(publicKey, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, strData as CFData, nil) else {
            print("error: publickey encrpty is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        let encryptedData = encryptData as Data
        let encryptedBase64Str = encryptedData.base64EncodedString()
        complete(SEInfoRef(statusIn: .SUCCESS, keyIn: encryptedBase64Str))
    }
    
    // 解密
    func decrypt(str:String,complete:complete) -> Void {
        if str.isEmpty{
            print("error: decrypt str is nil")
            complete(SEInfoRef(statusIn: .PARAM_ERROR, keyIn: nil))
            return
        }
        // 是否生成过
        if !isExistKeyPair() {
            print("error: please generate keypair")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 获取公钥
        guard getKeyPair() != nil else {
            print("error: publickey is nil")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 解Base64
        guard let strData = Data(base64Encoded: str) else {
            print("error: base64 dencrypt is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        if !SecKeyIsAlgorithmSupported(queryPrivateKey()!, SecKeyOperationType.decrypt, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM) {
            print("error: private key not support")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        // 解密
        guard let decryptData = SecKeyCreateDecryptedData(kEccPrivateKey!, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, strData as CFData, nil) else {
            print("error: decrypt data is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        let decryptedData = decryptData as Data
        guard let decryptedStr = String(data: decryptedData, encoding: .utf8) else {
            print("error: data to str is failed")
            complete(SEInfoRef(statusIn: .FAILED, keyIn: nil))
            return
        }
        complete(SEInfoRef(statusIn: .SUCCESS, keyIn: decryptedStr))
    }
    
    // 是否存在
    func isExistKeyPair() -> Bool {
        if queryPrivateKey() == nil {
            return false
        }
        return true
    }
    
    // 删除密钥对
    func delete() -> Bool {
        let dict = NSMutableDictionary()
        dict.setValue(true, forKey: kSecReturnRef as String)
        dict.setValue(kSecClassKey, forKey: kSecClass as String)
        dict.setValue(kSecMessECCLabel, forKey: kSecAttrLabel as String)
        dict.setValue(kSecAttrTokenIDSecureEnclave, forKey: kSecAttrTokenID as String)
        
        let status = SecItemDelete(dict)
        if  status != noErr {
            return false
        }
        return true
    }
    
    // 获取PublicKey
    private func getKeyPair() -> String? {
        // 是否生成过
        if let (tempPrivateKey,tempPublicKey) = queryKeyPair() {
            kEccPublicKey = tempPublicKey
            kEccPrivateKey = tempPrivateKey
            
            let externalKey = SecKeyCopyExternalRepresentation(tempPublicKey, nil)
            let externalKeyData = externalKey! as Data
            let externalKeyBase64Str = externalKeyData.base64EncodedString()
            return externalKeyBase64Str
        }
        // 生成公私钥
        guard let aclObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage], nil) else {
            print("error: acl object is failed")
            return nil
        }
        // 私钥参数
        let privateKeyParams = NSMutableDictionary()
        privateKeyParams.setValue(aclObject, forKey: kSecAttrAccessControl as String)
        privateKeyParams.setValue(true, forKey: kSecAttrIsPermanent as String)
        // 全局参数
        let params = NSMutableDictionary()
        params.setValue(kSecMessECCLabel, forKey: kSecAttrLabel as String)
        params.setValue(privateKeyParams, forKey: kSecPrivateKeyAttrs as String)
        params.setValue(kSecMessECCKeySize, forKey: kSecAttrKeySizeInBits as String)
        params.setValue(kSecAttrTokenIDSecureEnclave, forKey: kSecAttrTokenID as String)
        params.setValue(kSecAttrKeyTypeECSECPrimeRandom, forKey: kSecAttrKeyType as String)
        // 生成私钥
        guard let eccPrivateKey = SecKeyCreateRandomKey(params, nil) else {
            print("error: create private is failed")
            return nil
        }
        // 生成公钥
        guard let eccPublicKey = SecKeyCopyPublicKey(eccPrivateKey) else {
            print("error: create ecc publickey is failed")
            return nil
        }
        // 导出公钥
        let externalKey = SecKeyCopyExternalRepresentation(eccPublicKey, nil)
        let externalKeyData = externalKey! as Data
        let externalKeyBase64Str = externalKeyData.base64EncodedString()
        // 变量属性
        kEccPublicKey = eccPublicKey
        kEccPrivateKey = eccPrivateKey
        // 返回
        return externalKeyBase64Str
    }
    
    // 是否生成
    private func queryKeyPair() -> (SecKey,SecKey)? {
        guard let eccPrivateKey = queryPrivateKey() else {
            print("error: get private is error")
            return nil
        }
        guard let eccPublicKey = SecKeyCopyPublicKey(eccPrivateKey) else {
            print("error: get publickey is error")
            return nil
        }
        return (eccPrivateKey,eccPublicKey)
    }
    
    // 查询公私钥
    private func queryPrivateKey() -> SecKey? {
        let dict = NSMutableDictionary()
        dict.setValue(true, forKey: kSecReturnRef as String)
        dict.setValue(kSecClassKey, forKey: kSecClass as String)
        dict.setValue(256, forKey: kSecAttrKeySizeInBits as String)
        dict.setValue(kSecMessECCLabel, forKey: kSecAttrLabel as String)
        dict.setValue(kSecAttrKeyTypeECSECPrimeRandom, forKey: kSecAttrKeyType as String)
        
        // 生成
        var mEccPrivateKey:CFTypeRef?
        let status = SecItemCopyMatching(dict, &mEccPrivateKey)
        
        // 生成是否有生成
        if status != noErr {
            return nil
        }
        return (mEccPrivateKey as! SecKey)
    }
}
