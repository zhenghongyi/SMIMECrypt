//
//  SMCrypt.m
//  SMIMECrypt
//
//  Created by zhenghongyi on 2024/11/8.
//

#import "SMCrypt.h"
#import <Security/Security.h>
#import "NSString+Base64Format.h"

@interface SMCertificate ()

@property (nonatomic, readwrite, strong) NSString* certificate;
@property (nonatomic, readwrite, strong) NSString* privateKey;
@property (nonatomic, readwrite, strong) NSString* password;

@property (nonatomic, readwrite, strong) NSString* serialNumber;
@property (nonatomic, readwrite, strong) NSString* issuer;
@property (nonatomic, readwrite, strong) NSString* subject;
@property (nonatomic, readwrite, strong) NSString* expiry;

@property (nonatomic, readwrite, assign) BOOL invalid;

@property (nonatomic, readwrite, strong) NSString* errorMsg;

@end

@implementation SMCertificate

- (instancetype)initWithSMIMECer:(SMIMECer)scer {
    self = [super init];
    if (self) {
        if (scer.cer && strlen(scer.cer) > 0) {
            self.certificate = [[NSString alloc] initWithUTF8String:scer.cer];
        }
        if (scer.key && strlen(scer.key) > 0) {
            self.privateKey = [[NSString alloc] initWithUTF8String:scer.key];
        }
        if (scer.serialNumber && strlen(scer.serialNumber) > 0) {
            self.serialNumber = [[NSString alloc] initWithUTF8String:scer.serialNumber];
        }
        if (scer.issuer && strlen(scer.issuer) > 0) {
            self.issuer = [[NSString alloc] initWithUTF8String:scer.issuer];
        }
        if (scer.subject && strlen(scer.subject) > 0) {
            self.subject = [[NSString alloc] initWithUTF8String:scer.subject];
        }
        if (scer.expiry && strlen(scer.expiry) > 0) {
            self.expiry = [[NSString alloc] initWithUTF8String:scer.expiry];
        }
        [self certificateVerify];
    }
    return self;
}

- (instancetype)initWithErrorMsg:(NSString *)errorMsg {
    self = [super init];
    if (self) {
        self.errorMsg = errorMsg;
    }
    return self;
}

+ (instancetype)Certificate:(NSString *)certificate privateKey:(NSString *)privateKey password:(NSString *)password {
    SMCertificate* cmcer = [SMCrypt getCertInfo:certificate];
    cmcer.privateKey = privateKey;
    cmcer.password = password;
    return cmcer;
}

- (void)certificateVerify {
    NSString* issureOrg = [[self issuerItem:@"O"] lowercaseString];
    if ([issureOrg isEqualToString:@"coremail"]) {
        self.invalid = false;
        return;
    }
    
    NSMutableString* content = [NSMutableString stringWithString:self.certificate];
    if ([content hasPrefix:@"-----BEGIN CERTIFICATE-----"]) {
        [content replaceOccurrencesOfString:@"-----BEGIN CERTIFICATE-----" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, content.length)];
        [content replaceOccurrencesOfString:@"-----END CERTIFICATE-----" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, content.length)];
        [content replaceOccurrencesOfString:@"\n" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, content.length)];
        [content replaceOccurrencesOfString:@"\r" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, content.length)];
    }

    NSData* certData = [[NSData alloc] initWithBase64EncodedString:content options:0];
    SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certData);
    
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates(cert, policy, &trust);
    
    SecTrustResultType result;
    status = SecTrustEvaluate(trust, &result);
    if (status == errSecSuccess &&
        (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed)) {
        self.invalid = false;
    } else {
        self.invalid = true;
    }
}


- (NSString *)issuer_CN {
    return [self issuerItem:@"CN"];
}

/**
 "C=CN/O=xx/CN=xxx/OU=xx/L=xx/ST=xx"
 - "C=" 代表国家
 - "O=" 代表组织
 - "OU=" 代表组织单位
 - "CN=" 代表通用名字
 - "L=" 代表地点
 - "ST=" 代表州或省份
 */
- (NSString *)issuerItem:(NSString *)itemKey {
    if (self.issuer) {
        NSArray<NSString*>* components = [self.issuer componentsSeparatedByString:@"/"];
        for (NSString* item in components) {
            if ([item hasPrefix:[NSString stringWithFormat:@"%@=", itemKey]]) {
                return [item substringFromIndex: itemKey.length + 1];
            }
        }
    }
    return nil;
}

/**
 - "C=" Country 代表国家
 - "O=" Organizatiion 代表组织
 - "OU=" Organizatiion Unit 代表组织单位
 - "CN=" Common Name 代表通用名字/公用名字/主机名，对于SSL证书是网站域名或IP地址，对于代码签名证书是申请单位名称，对客户端单位证书是证书申请者所在单位名称
 - "L=" Locality 代表地点
 - "ST=" State or Province 代表州或省份
 - "EMAIL="/"emailAddress=" 代表电子邮件地址
 */
- (NSString *)subject_email {
    if (self.subject) {
        NSArray<NSString*>* components = [self.subject componentsSeparatedByString:@"/"];
        NSString* emailPre = @"EMAIL=";
        NSString* emailAddPre = @"emailAddress=";
        for (NSString* item in components) {
            if ([item hasPrefix:emailPre]) {
                return [item substringFromIndex:emailPre.length];
            } else if ([item hasPrefix:emailAddPre]) {
                return [item substringFromIndex:emailAddPre.length];
            }
        }
    }
    return nil;
}

- (NSString *)expiry_local {
    if (self.expiry) {
        NSDateFormatter* df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"MMM  d HH:mm:ss yyyy z";
        df.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
        df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        
        NSDate* date = [df dateFromString:self.expiry];
        
        NSDateFormatter* localDf = [[NSDateFormatter alloc] init];
        localDf.locale = [NSLocale currentLocale];
        localDf.timeZone = [NSTimeZone localTimeZone];
        localDf.dateFormat = @"yyyy-MM-dd";
        return [localDf stringFromDate:date];
    }
    return nil;
}

- (NSDate *)expiryDate {
    if (self.expiry) {
        NSDateFormatter* df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"MMM  d HH:mm:ss yyyy z";
        df.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
        df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        
        NSDate* date = [df dateFromString:self.expiry];
        
        return date;
    }
    return nil;
}

- (BOOL)isExpiry {
    NSDate* nowDate = [NSDate date];
    if ([[self expiryDate] compare:nowDate] == NSOrderedAscending) {
        return true;
    }
    return false;
}

@end

@implementation SMCrypt

+ (SMCertificate *)getCertInfo:(NSString *)certificate {
    const char* cert = [certificate UTF8String];
    SMIMECer scer = getCertInfo(cert);
    if (scer.errorMsg) {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:scer.errorMsg]);
        return [[SMCertificate alloc] initWithErrorMsg:[[NSString alloc] initWithUTF8String:scer.errorMsg]];
    }
    return [[SMCertificate alloc] initWithSMIMECer:scer];
}

+ (BOOL)verifyMatch:(NSString *)privateKey password:(NSString *)password {
    const char* pri = [privateKey UTF8String];
    const char* pwd = [password UTF8String];
    char* errorMsg = verifyMatch(pri, pwd);
    if (errorMsg) {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:errorMsg]);
        return false;
    } else {
        return true;
    }
}

+ (NSString *)signature:(NSString *)message certificate:(NSString *)certificate privateKey:(NSString *)privateKey password:(NSString *)password detach:(BOOL)detach {
    const char* msg = [message UTF8String];
    const char* cer = [certificate UTF8String];
    const char* pri = [privateKey UTF8String];
    const char* pwd = [password UTF8String];
    char* errorMsg;
    const char* sign = signMessage(msg, cer, pri, pwd, detach ? 1 : 0, 1, &errorMsg);
    if (sign) {
        return [NSString stringWithUTF8String:sign];
    } else {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:errorMsg]);
        return nil;
    }
}

+ (SMCertificate *)detachVerifySignature:(NSString *)signature message:(NSString *)message {
    const char* sig = [signature UTF8String];
    const char* msg = [message UTF8String];
    SMIMECer scer = verifyDetachSignature(sig, msg);
    if (scer.errorMsg) {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:scer.errorMsg]);
        return [[SMCertificate alloc] initWithErrorMsg:[[NSString alloc] initWithUTF8String:scer.errorMsg]];
    }
    SMCertificate* certificate = [[SMCertificate alloc] initWithSMIMECer:scer];
    return certificate;
}

+ (SMCertificate *)attachVerifySignature:(NSString *)signature originStr:(NSString **)originStr {
    NSString* sigStr = signature;
    if (![signature hasPrefix:@"-----BEGIN CMS-----"]) {
        sigStr = [NSString stringWithFormat:@"-----BEGIN CMS-----\n%@", sigStr];
    }
    if (![signature hasSuffix:@"-----END CMS-----"]) {
        sigStr = [NSString stringWithFormat:@"%@\n-----END CMS-----", sigStr];
    }
    
    const char* sig = [sigStr UTF8String];
    char* original;
    SMIMECer scer = verifyAttchSignature(sig, &original);
    
    *originStr = [NSString stringWithUTF8String:original];
    if (scer.errorMsg) {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:scer.errorMsg]);
        return [[SMCertificate alloc] initWithErrorMsg:[[NSString alloc] initWithUTF8String:scer.errorMsg]];
    }
    return [[SMCertificate alloc] initWithSMIMECer:scer];
}

+ (NSString *)encrypt:(NSString *)message certificate:(NSArray<NSString *> *)certificates {
    const char* msg = [message UTF8String];
    char* cerChars[certificates.count];
    for (int i = 0; i < certificates.count; i ++) {
        const char* cer = [certificates[i] UTF8String];
        cerChars[i] = (char *)cer;
    }
    char* errorMsg;
    const char* encrypt = encryptMessage(msg, (const char**)cerChars, (int)certificates.count, 1, &errorMsg);
    if (encrypt) {
        return [NSString stringWithUTF8String:encrypt];
    } else {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:errorMsg]);
        return nil;
    }
}

+ (NSString *)decrypt:(NSString *)message privateKey:(NSString *)privateKey password:(NSString *)password {
    NSString* temp = [message stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([temp hasPrefix:@"-----BEGIN CMS-----"] == false) {
        temp = [NSString stringWithFormat:@"-----BEGIN CMS-----\n%@", temp];
    }
    if ([temp hasSuffix:@"-----END CMS-----"] == false) {
        temp = [NSString stringWithFormat:@"%@\n-----END CMS-----\n", temp];
    }
    
    const char* msg = [temp UTF8String];
    const char* pri = [privateKey UTF8String];
    const char* pwd = [password UTF8String];
    char* errorMsg;
    const char* decrypt = decryptMessage(msg, pri, pwd, 1, &errorMsg);
    if (decrypt) {
        return [NSString stringWithUTF8String:decrypt];
    } else {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:errorMsg]);
        return nil;
    }
}

+ (SMCertificate *)parseP12File:(NSString *)filePath password:(NSString *)password {
    // OpenSSL 3.x版本默认不支持OpenSSL 1.x的旧的算法生成的p12，如果3.x要启用旧算法相对比较麻烦，在3.x无法解析p12文件的情况下，改为系统能力解析
    const char* path = [filePath UTF8String];
    const char* pwd = [password UTF8String];
    SMIMECer scer = parserP12(path, pwd);
    if (scer.errorMsg == nil) {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:scer.errorMsg]);
        return [[SMCertificate alloc] initWithErrorMsg: [[NSString alloc] initWithUTF8String:scer.errorMsg]];
    }
    
    NSData *p12Data = [[NSData alloc] initWithContentsOfFile:filePath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)p12Data;

    // Create Identity
    CFArrayRef keyref = nil;
    OSStatus securityError = noErr;
    SecIdentityRef identity;

    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { (__bridge CFStringRef)password };

    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    securityError = SecPKCS12Import(inPKCS12Data, optionsDictionary, &keyref);
    CFRelease(optionsDictionary);
    
    if (securityError != noErr) {
        if (keyref != nil) {
            CFRelease(keyref);
        }
        if (securityError == errSecAuthFailed) {
            return [[SMCertificate alloc] initWithErrorMsg:@"密码错误"];
        }
        return [[SMCertificate alloc] initWithErrorMsg:@"SecPKCS12Import转换失败"];
    }

    CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(keyref, 0);
    const void *tempIdentity = NULL;
    tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
    identity = (SecIdentityRef)tempIdentity;
    
    NSString* cer;
    NSString* key;
    
    // Identity
    SecCertificateRef certRef;
    OSStatus certExtractStatus = SecIdentityCopyCertificate(identity, &certRef);

    if (certExtractStatus == errSecSuccess) {
        CFDataRef certDataRef = SecCertificateCopyData(certRef);
        NSData *certData = (__bridge NSData *)certDataRef;
        cer = [certData base64EncodedStringWithOptions:0];
        cer = [cer cerBase64format];
        if (certDataRef != NULL) {
            CFRelease(certDataRef);
        }
    } else {
        return [[SMCertificate alloc] initWithErrorMsg:@"SecIdentityCopyCertificate转换失败"];
    }

    // Private Key
    SecKeyRef privateKeyRef;
    securityError = SecIdentityCopyPrivateKey(identity, &privateKeyRef);
    if (securityError != noErr) {
        return [[SMCertificate alloc] initWithErrorMsg:@"SecIdentityCopyPrivateKey转换失败"];
    }
    
    CFErrorRef error;
    CFDataRef cfData = SecKeyCopyExternalRepresentation(privateKeyRef, &error);
    if (!cfData) {
        NSLog(@"Error obtaining external representation of key: %@", (__bridge NSError *)error);
        return [[SMCertificate alloc] initWithErrorMsg:@"SecKeyCopyExternalRepresentation转换失败"];
    }

    const unsigned char *privateKeyBytes = CFDataGetBytePtr(cfData);
    long privateKeySize = CFDataGetLength(cfData);
    
    char* errorMsg;
    char* priChar = getPriKeyFromP12(privateKeyBytes, (int)privateKeySize, &errorMsg);
    if (priChar) {
        key = [NSString stringWithUTF8String:priChar];
    } else {
        NSLog(@"[SMIMECrypt] %@", [[NSString alloc] initWithUTF8String:errorMsg]);
        return [[SMCertificate alloc] initWithErrorMsg:[[NSString alloc] initWithUTF8String:errorMsg]];
    }
    
    CFRelease(keyref);
    
    return [SMCertificate Certificate:cer privateKey:key password:nil];
}

@end

