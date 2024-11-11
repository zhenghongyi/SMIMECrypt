//
//  NSString+Base64Format.m
//  Coremail
//
//  Created by zhenghongyi on 2024/10/17.
//

#import "NSString+Base64Format.h"

@implementation NSString (Base64Format)

- (NSString *)cerBase64format {
    if ([self hasPrefix:@"-----BEGIN CERTIFICATE-----"] && [self hasSuffix:@"-----END CERTIFICATE-----"]) {
        return self;
    } else {
        NSMutableString* cer = [NSMutableString stringWithString:@"-----BEGIN CERTIFICATE-----\r\n"];
        int i = 0;
        while (i + 64 < self.length) {
            [cer appendString:[self substringWithRange:NSMakeRange(i, 64)]];
            [cer appendString:@"\r\n"];
            i = i+ 64;
        }
        if ([self length] > i) {
            [cer appendString:[self substringWithRange:NSMakeRange(i, self.length - i)]];
            [cer appendString:@"\r\n"];
        }
        [cer appendString:@"-----END CERTIFICATE-----"];
        return cer;
    }
}

@end
