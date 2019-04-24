//
//  ViewController.swift
//  SecureEnclaveUse
//
//  Created by Kevin on 2019/4/19.
//  Copyright © 2019 Kevin. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var inputStr: UITextField!
    @IBOutlet weak var decryptSignStr: UITextView!
    @IBOutlet weak var encryptVerifyStr: UITextView!
    
    @IBOutlet weak var deleteResult: UITextView!
    @IBOutlet weak var isExistResult: UITextView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
}

// MARK: - 加密/解密公私钥
extension ViewController {
    
    // 加密
    @IBAction func clickEncrypt(_ sender: Any) {
        SecureEnclaveUtil.shareInstnace.encrypt(str: inputStr.text ?? "") { (info) in
            if info.status != .SUCCESS {
                encryptVerifyStr.text = String(describing: info.status)
                return
            }
            // 加密成功
            encryptVerifyStr.text = info.key
        }
    }
    
    // 解密
    @IBAction func clickDecrypt(_ sender: Any) {
        SecureEnclaveUtil.shareInstnace.decrypt(str: encryptVerifyStr.text) { (info) in
            if info.status != .SUCCESS {
                decryptSignStr.text = String(describing: info.status)
                return
            }
            // 解密成功
            decryptSignStr.text = info.key
        }
    }
    
    // 是否生成过
    @IBAction func clickIsExist(_ sender: Any) {
        let result = SecureEnclaveUtil.shareInstnace.isExistKeyPair()
        isExistResult.text = String(describing: result)
    }
    
    // 删除
    @IBAction func clickDeleteEcc(_ sender: Any) {
        let result = SecureEnclaveUtil.shareInstnace.delete()
        deleteResult.text = String(describing: result)
    }
}

// MARK: - 签名/验签公私钥
extension ViewController {
    
    // 签名
    @IBAction func clickSign(_ sender: Any) {
        SecureEnclaveUtil.shareInstnace.sign(str: inputStr.text ?? "") { (info) in
            if info.status != .SUCCESS {
                encryptVerifyStr.text = String(describing: info.status)
                return
            }
            // 签名成功
            encryptVerifyStr.text = info.key
        }
    }
    
    // 验签
    @IBAction func clickVerify(_ sender: Any) {
        let result = SecureEnclaveUtil.shareInstnace.verify(str: inputStr.text ?? "", signatureStr: encryptVerifyStr.text ?? "")
        decryptSignStr.text = String(describing: result)
    }
    
    // 是否生成过
    @IBAction func clickIsExistSign(_ sender: Any) {
        let result = SecureEnclaveUtil.shareInstnace.isExistSignKeyPair()
        isExistResult.text = String(describing: result)
    }
    
    // 删除
    @IBAction func clickDeleteSign(_ sender: Any) {
        let result = SecureEnclaveUtil.shareInstnace.deleteSign()
        deleteResult.text = String(describing: result)
    }
}

extension ViewController {
    
    // 隐藏键盘
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        view.endEditing(true)
    }
}

