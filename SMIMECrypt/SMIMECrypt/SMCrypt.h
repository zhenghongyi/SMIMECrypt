//
//  SMCrypt.h
//  SMIMECrypt
//
//  Created by zhenghongyi on 2024/11/8.
//

#import <Foundation/Foundation.h>
#import <SMIMECrypt/SMIME.h>

@interface SMCertificate : NSObject

@property (nonatomic, readonly, strong) NSString* certificate;
@property (nonatomic, readonly, strong) NSString* privateKey;
@property (nonatomic, readonly, strong) NSString* password;

@property (nonatomic, readonly, strong) NSString* serialNumber;
@property (nonatomic, readonly, strong) NSString* issuer;
@property (nonatomic, readonly, strong) NSString* subject;
@property (nonatomic, readonly, strong) NSString* expiry;

@property (nonatomic, readonly, assign) BOOL invalid;

@property (nonatomic, readonly, strong) NSString* errorMsg;

- (instancetype)initWithSMIMECer:(SMIMECer)scer;

- (instancetype)initWithErrorMsg:(NSString *)errorMsg;

+ (instancetype)Certificate:(NSString *)certificate privateKey:(NSString *)privateKey password:(NSString *)password;

- (NSString *)issuer_CN;

- (NSString *)subject_email;

- (NSString *)expiry_local;

- (NSDate *)expiryDate;

- (BOOL)isExpiry;

@end

@interface SMCrypt : NSObject


// 获取证书信息
+ (SMCertificate *)getCertInfo:(NSString *)certificate;

// 校验私钥和密码是否配对
+ (BOOL)verifyMatch:(NSString *)privateKey password:(NSString *)password;

/**
 签名
 @param message 待签名信息
 @param certificate 证书
 @param privateKey 证书配对的私钥
 @param password 私钥配对的密码，无密码则为nil
 @param detach 是否detach方式签名
 @return 签名后信息
 @desc 签名方式分detach和attach，区别在于前者不会把待签名信息包含在签名里
 */
+ (NSString *)signature:(NSString *)message certificate:(NSString *)certificate privateKey:(NSString *)privateKey password:(NSString *)password detach:(BOOL)detach;
/**
 detach方式验签
 @param signature 签名
 @param message 签名的原文信息
 @return CMCertificate证书结构
 */
+ (SMCertificate *)detachVerifySignature:(NSString *)signature message:(NSString *)message;
/**
 attach方式验签
 @param signature 签名
 @param originStr 待从签名中提取原文信息
 @return CMCertificate证书结构
 */
+ (SMCertificate *)attachVerifySignature:(NSString *)signature originStr:(NSString **)originStr;

/**
 加密
 @param message 待加密信息
 @param certificates 用于加密的证书数组
 @return 加密后信息
 */
+ (NSString *)encrypt:(NSString *)message certificate:(NSArray<NSString *> *)certificates;
/**
 解密
 @param message 密文信息
 @param privateKey 用于解密的私钥
 @param password 私钥配对的密码
 @return 解密后信息
 */
+ (NSString *)decrypt:(NSString *)message privateKey:(NSString *)privateKey password:(NSString *)password;


/**
 解析p12/pfx文件，提取证书与密钥
 @param filePath 证书路径
 @param password 证书配对的密码
 @return 解析获取到的证书和密钥
 */
+ (SMCertificate *)parseP12File:(NSString *)filePath password:(NSString *)password;

@end
