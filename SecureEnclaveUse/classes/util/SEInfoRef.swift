//
//  SEInfoRef.swift
//  SecureEnclaveUse
//
//  Created by Kevin on 2019/4/23.
//  Copyright © 2019 Kevin. All rights reserved.
//

import UIKit

enum SEStatus {
    
    case FAILED                 // 失败
    case SUCCESS                // 成功
    case PARAM_ERROR            // 入参错误
}

struct SEInfoRef {
    
    var key:String?
    var status:SEStatus
    
    init(statusIn:SEStatus,keyIn:String?) {
        key =  keyIn
        status = statusIn
    }
    
}
