//
//  SMIME.h
//  Lunkr
//
//  Created by zhenghongyi on 2024/8/6.
//

#ifndef SMIME_h
#define SMIME_h

#include <stdio.h>

typedef struct {
    char* cer;
    char* key;
    
    char* serialNumber;
    char* issuer;
    char* subject;
    char* expiry;
    
    char* errorMsg;
} SMIMECer;


SMIMECer getCertInfo(const char* certificate);

char* verifyMatch(const char* prikey, const char* password);

char* signMessage(const char* message, const char* certificate, const char* privateKey, const char* password, int detach, int useCMS, char** errorMsg);

SMIMECer verifyDetachSignature(const char* signature, const char* message);

SMIMECer verifyAttchSignature(const char* signature, char** outMessage);

char* encryptMessage(const char* message, const char* certificates[], int certificatesNumber, int useCMS, char** errorMsg);

char* decryptMessage(const char* message, const char* privateKey, const char* password, int useCMS, char** errorMsg);

SMIMECer parserP12(const char* p12Path, const char* password);

char* getPriKeyFromP12(const void *buf, int len, char** errorMsg);

#endif /* SMIME_h */
