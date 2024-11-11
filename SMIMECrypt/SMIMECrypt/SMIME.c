//
//  SMIME.c
//  Lunkr
//
//  Created by zhenghongyi on 2024/8/6.
//  Copyright © 2024 Coremail论客. All rights reserved.
//

#include "SMIME.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
 
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/cms.h>
#include <openssl/x509_vfy.h>

static int x509_store_callback(int ok, X509_STORE_CTX *ctx)
{
    /* Pretend the certificate issuer is valid... */
    return 1;
}

static char* fatal(char *msg, int lineNum)
{
    unsigned long err_code = ERR_get_error();
    char *err_msg = ERR_error_string(err_code, NULL);
    printf("Error: %s\n", err_msg);
    char* output = malloc(sizeof(char) * 100);
    if(output != NULL) {
        sprintf(output, "%s %d:%s", msg, lineNum, err_msg);
        return output;
    }
    return err_msg;
}

char* bioToChar(BIO* bio) {
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    BIO_set_close(bio, BIO_NOCLOSE); // So BIO_free() leaves BUF_MEM alone
    char *data = malloc(mem->length + 1);
    memcpy(data, mem->data, mem->length + 1);
    
    size_t mem_length = mem->length;
    
    BUF_MEM_free(mem);
    
    // 真机环境下，解密后原文后会附带些乱码，这里需要做截取
    data[mem_length] = '\0';
    return data;
}

// 调用getX509Info后，X509对象似乎引用计数会减少，不需要再释放
SMIMECer getX509Info(X509 *x509) {
    SMIMECer scer;
    
    // 获取序列号
    ASN1_INTEGER *serial = X509_get_serialNumber(x509);
    if (serial == NULL) {
        scer.errorMsg = fatal("getX509Info X509_get_serialNumber", __LINE__);
        return scer;
    }
    BIGNUM *bnser = ASN1_INTEGER_to_BN(serial, NULL);
    char *ser_hex = BN_bn2hex(bnser);
    scer.serialNumber = ser_hex;
    BN_free(bnser);
    
    // 获取证书签发者和使用者信息
    X509_NAME *issuer_name = X509_get_issuer_name(x509);
    if (issuer_name == NULL) {
        scer.errorMsg = fatal("getX509Info X509_get_issuer_name", __LINE__);
        return scer;
    }
    X509_NAME *subject_name = X509_get_subject_name(x509);
    if (subject_name == NULL) {
        scer.errorMsg = fatal("getX509Info X509_get_subject_name", __LINE__);
        return scer;
    }
    char *issuer_buffer = (char *) malloc(256);
    char *subject_buffer = (char *) malloc(256);

    X509_NAME_oneline(issuer_name, issuer_buffer, 256);
    scer.issuer = issuer_buffer;

    X509_NAME_oneline(subject_name, subject_buffer, 256);
    scer.subject = subject_buffer;
    
    X509_NAME_free(issuer_name);
    X509_NAME_free(subject_name);

    // 获取证书到期时间
    ASN1_TIME *not_after = X509_get_notAfter(x509);
    if (not_after == NULL) {
        scer.errorMsg = fatal("getX509Info X509_get_notAfter", __LINE__);
        return scer;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, not_after);
    char *expiry_date = (char *) malloc(256);
    memset(expiry_date, 0, 256);
    BIO_gets(bio, expiry_date, 256);
    scer.expiry = expiry_date;

    BIO_free(bio);
    ASN1_TIME_free(not_after);
    
    scer.errorMsg = NULL;
    scer.cer = NULL;
    scer.key = NULL;
    
    return scer;
}

SMIMECer getCertInfo(const char* certificate) {
    SMIMECer scer;
    
    BIO *bio = NULL;
    X509 *x509 = NULL;
  
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    bio = BIO_new_mem_buf(certificate, -1);
    if (bio == NULL) {
        scer.errorMsg = fatal("getCertInfo BIO_new_mem_buf", __LINE__);
        return scer;
    }
    x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        scer.errorMsg = fatal("getCertInfo PEM_read_bio_X509", __LINE__);
        return scer;
    }
    scer = getX509Info(x509);
    scer.cer = (char *)certificate;
    
    BIO_free(bio);
    
    return scer;
}

char* verifyMatch(const char* prikey, const char* password) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    EVP_PKEY *pkey = NULL;
    BIO *bio;
    bio = BIO_new_mem_buf(prikey, -1);
    if (bio == NULL) {
        return fatal("verifyMatch BIO_new_mem_buf", __LINE__);
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, password);
    if (pkey == NULL) {
        BIO_free_all(bio);
        return fatal("verifyMatch PEM_read_bio_PrivateKey", __LINE__);
    }

    EVP_PKEY_free(pkey);
    BIO_free_all(bio);
    return NULL;
}

char* signMessage(const char* message, const char* certificate, const char* privateKey, const char* password, int detach, int useCMS, char** errorMsg) {
    BIO *bio_stack, *bio_out, *bio_pkey, *bio_content, *bio_cert;
    STACK_OF(X509) *certs;
    EVP_PKEY *pkey;
    
    X509 *cert;
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    // BIO链，用来统一释放所有BIO对象
    bio_stack = BIO_new(BIO_s_mem());
    if (bio_stack == NULL) {
        *errorMsg = fatal("signMessage BIO_new", __LINE__);
        return NULL;
    }
    
    bio_content = BIO_new_mem_buf((char *)message, (int)strlen(message));
    if (bio_content == NULL) {
        *errorMsg = fatal("signMessage BIO_new_mem_buf", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_content);
    
    bio_cert = BIO_new_mem_buf(certificate, (int)(strlen(certificate)));
    if (bio_cert == NULL) {
        *errorMsg = fatal("signMessage BIO_new_mem_buf", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_cert);
    
    bio_pkey = BIO_new_mem_buf(privateKey, (int)strlen(privateKey));
    if (bio_pkey == NULL) {
        *errorMsg = fatal("signMessage BIO_new_mem_buf", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_pkey);
 
    pkey = PEM_read_bio_PrivateKey(bio_pkey, NULL, NULL, (char *)password);
    if (pkey == NULL) {
        *errorMsg = fatal("signMessage PEM_read_bio_PrivateKey", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
 
    certs = sk_X509_new_null();
    if (certs == NULL) {
        *errorMsg = fatal("signMessage sk_X509_new_null", __LINE__);
        EVP_PKEY_free(pkey);
        BIO_free_all(bio_stack);
        return NULL;
    }
 
    cert = PEM_read_bio_X509_AUX(bio_cert, NULL, NULL, NULL);
    if (cert == NULL) {
        *errorMsg = fatal("signMessage PEM_read_bio_X509_AUX", __LINE__);
        EVP_PKEY_free(pkey);
        BIO_free_all(bio_stack);
        return NULL;
    }
    sk_X509_push(certs, cert);
    
    bio_out = BIO_new(BIO_s_mem());
    if (bio_out == NULL) {
        *errorMsg = fatal("signMessage BIO_new", __LINE__);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_out);
    
    int flags = detach > 0 ? PKCS7_DETACHED : PKCS7_BINARY;
    if (useCMS) {
        CMS_ContentInfo* cms = CMS_sign(cert, pkey, NULL, bio_content, flags);
        if (cms == NULL) {
            *errorMsg = fatal("signMessage CMS_sign", __LINE__);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio_stack);
            return NULL;
        }
        if (PEM_write_bio_CMS(bio_out, cms) != 1) {
            *errorMsg = fatal("signMessage PEM_write_bio_CMS", __LINE__);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio_stack);
            return NULL;
        }
        CMS_ContentInfo_free(cms);
    } else {
        PKCS7 *p7 = PKCS7_sign(cert, pkey, certs, bio_content, flags);
        if (p7 == NULL) {
            *errorMsg = fatal("signMessage PKCS7_sign", __LINE__);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio_stack);
            return NULL;
        }
        if (PEM_write_bio_PKCS7(bio_out, p7) != 1) {
            *errorMsg = fatal("signMessage PEM_write_bio_PKCS7", __LINE__);
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(bio_stack);
            return NULL;
        }
        PKCS7_free(p7);
    }
    char* data = bioToChar(bio_out);
    
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(bio_stack);
    
    return data;
}

SMIMECer verifyDetachSignature(const char* signature, const char* message) {
    SMIMECer scer;
    
    // Create a BIO object for base64 decoding
    BIO *b64 = BIO_new(BIO_f_base64());
    // Create source BIO memory
    BIO *signature_bio = BIO_new_mem_buf((void*)signature, -1);
    signature_bio = BIO_push(b64, signature_bio);
    
    BIO *bio_in = BIO_new_mem_buf((char *)message, -1);
    if (bio_in == NULL) {
        BIO_free_all(signature_bio);
        scer.errorMsg = fatal("verifyDetachSignature BIO_new_mem_buf", __LINE__);
        return scer;
    }
    
    CMS_ContentInfo *cms = d2i_CMS_bio(signature_bio, NULL);
    if (cms == NULL) {
        BIO_free_all(signature_bio);
        scer.errorMsg = fatal("verifyDetachSignature d2i_CMS_bio", __LINE__);
        return scer;
    }
    if (CMS_verify(cms, NULL, NULL, bio_in, NULL, CMS_NO_SIGNER_CERT_VERIFY) < 1) {
        BIO_free_all(signature_bio);
        CMS_ContentInfo_free(cms);
        scer.errorMsg = fatal("verifyDetachSignature CMS_verify", __LINE__);
        return scer;
    }
    BIO_free_all(signature_bio);
    
    STACK_OF(X509)* signers = CMS_get0_signers(cms);
    if (!signers || sk_X509_num(signers) != 1) {
        CMS_ContentInfo_free(cms);
        scer.errorMsg = fatal("verifyDetachSignature CMS_get0_signers", __LINE__);
        return scer;
    }
    
    X509* cert = sk_X509_value(signers, 0);
    scer = getX509Info(cert);
    
    BIO *bioCert = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(bioCert, cert) < 1) {
        scer.errorMsg = fatal("verifyDetachSignature PEM_write_bio_X509", __LINE__);
        return scer;
    }
    
    char *cert_str = bioToChar(bioCert);
    scer.cer = cert_str;
    scer.errorMsg = NULL;
    
    BIO_free(bioCert);
    
    return scer;
}

SMIMECer verifyAttchSignature(const char* signature, char** outMessage) {
    SMIMECer scer;
    
    // Create a BIO object for base64 decoding
    BIO *b64 = BIO_new(BIO_f_base64());
    // Create source BIO memory
    BIO *signature_bio = BIO_new_mem_buf((void*)signature, -1);
    signature_bio = BIO_push(b64, signature_bio);

    CMS_ContentInfo *cms = d2i_CMS_bio(signature_bio, NULL);
    if (cms == NULL) {
        BIO_free_all(signature_bio);
        scer.errorMsg = fatal("verifyAttchSignature d2i_CMS_bio", __LINE__);
        return scer;
    }
    
    BIO *bio_out = BIO_new(BIO_s_mem());
    if (bio_out == NULL) {
        BIO_free_all(signature_bio);
        scer.errorMsg = fatal("verifyAttchSignature BIO_new", __LINE__);
        return scer;
    }
    BIO_push(signature_bio, bio_out);
    
    if (CMS_verify(cms, NULL, NULL, NULL, bio_out, CMS_NO_SIGNER_CERT_VERIFY) < 1) {
        BIO_free_all(signature_bio);
        CMS_ContentInfo_free(cms);
        scer.errorMsg = fatal("verifyAttchSignature CMS_verify", __LINE__);
        return scer;
    }
    
    *outMessage = bioToChar(bio_out);
    
    STACK_OF(X509)* signers = CMS_get0_signers(cms);
    if (!signers || sk_X509_num(signers) != 1) {
        BIO_free_all(signature_bio);
        scer.errorMsg = fatal("verifyAttchSignature CMS_get0_signers", __LINE__);
        return scer;
    }
    X509* cert = sk_X509_value(signers, 0);
    scer = getX509Info(cert);
    
    BIO *bioCert = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(bioCert, cert) < 1) {
        BIO_free_all(signature_bio);
        scer.errorMsg = fatal("verifyAttchSignature PEM_write_bio_X509", __LINE__);
        return scer;
    }
    
    char *cert_str = bioToChar(bioCert);
    
    scer.cer = cert_str;
    scer.key = "";
    scer.errorMsg = NULL;
    
    BIO_free_all(signature_bio);
    BIO_free(bioCert);
    
    return scer;
}

char* encryptMessage(const char* message, const char* certificates[], int certificatesNumber, int useCMS, char** errorMsg) {
    BIO *bio_stack, *bio_content, *bio_out;
    STACK_OF(X509) *certs;
    const EVP_CIPHER *cipher;
    X509_STORE *store;
    X509 *cert;
 
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
 
    cipher = EVP_des_ede3_cbc();
    if (cipher == NULL) {
        *errorMsg = fatal("encryptMessage EVP_des_ede3_cbc", __LINE__);
        return NULL;
    }
 
    certs = sk_X509_new_null();
    if (certs == NULL) {
        *errorMsg = fatal("encryptMessage sk_X509_new_null", __LINE__);
        return NULL;
    }
    
    bio_stack = BIO_new(BIO_s_mem());
    for (int i = 0; i < certificatesNumber; i ++) {
        BIO* bio_cert = BIO_new_mem_buf(certificates[i], (int)(strlen(certificates[i])));
        if (bio_cert == NULL) {
            *errorMsg = fatal("encryptMessage BIO_new_mem_buf", __LINE__);
            return NULL;
        }
        BIO_push(bio_stack, bio_cert);
     
        cert = PEM_read_bio_X509_AUX(bio_cert, NULL, NULL, NULL);
        if (cert == NULL) {
            *errorMsg = fatal("encryptMessage PEM_read_bio_X509_AUX", __LINE__);
            BIO_free_all(bio_stack);
            return NULL;
        }
        sk_X509_push(certs, cert);
    }
 
    store = X509_STORE_new();
    if (store == NULL) {
        *errorMsg = fatal("encryptMessage X509_STORE_new", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    X509_STORE_set_verify_cb(store, x509_store_callback);
 
    bio_content = BIO_new_mem_buf((char *)message, (int)strlen(message));
    if (bio_content == NULL) {
        *errorMsg = fatal("encryptMessage BIO_new_mem_buf", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_content);
        
    bio_out = BIO_new(BIO_s_mem());
    if (bio_out == NULL) {
        *errorMsg = fatal("encryptMessage BIO_new", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_out);
 
    if (useCMS) {
        CMS_ContentInfo* cms = CMS_encrypt(certs, bio_content, cipher, 0);
        if (cms == NULL) {
            *errorMsg = fatal("encryptMessage CMS_encrypt", __LINE__);
            BIO_free_all(bio_stack);
            return NULL;
        }
        if (PEM_write_bio_CMS(bio_out, cms) != 1) {
            *errorMsg = fatal("encryptMessage PEM_write_bio_CMS", __LINE__);
            BIO_free_all(bio_stack);
            CMS_ContentInfo_free(cms);
            return NULL;
        }
        CMS_ContentInfo_free(cms);
    } else {
        PKCS7 *p7 = PKCS7_encrypt(certs, bio_content, cipher, 0);
        if (p7 == NULL) {
            *errorMsg = fatal("encryptMessage PKCS7_encrypt", __LINE__);
            BIO_free_all(bio_stack);
            return NULL;
        }
        if (PEM_write_bio_PKCS7(bio_out, p7) != 1) {
            *errorMsg = fatal("encryptMessage PEM_write_bio_PKCS7", __LINE__);
            BIO_free_all(bio_stack);
            PKCS7_free(p7);
            return NULL;
        }
        PKCS7_free(p7);
    }
    
    char* data = bioToChar(bio_out);
    BIO_free_all(bio_stack);
    
    return data;
}

char* decryptMessage(const char* message, const char* privateKey, const char* password, int useCMS, char** errorMsg) {
    BIO *bio_stack, *bio_in, *bio_out, *bio_pkey;
    
    EVP_PKEY *pkey;
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    bio_stack = BIO_new(BIO_s_mem());
    if (bio_stack == NULL) {
        *errorMsg = fatal("decryptMessage BIO_new", __LINE__);
        return NULL;
    }
    
    bio_in = BIO_new_mem_buf((char *)message, -1);
    if (bio_in == NULL) {
        *errorMsg = fatal("decryptMessage BIO_new_mem_buf", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_in);
    bio_out = BIO_new(BIO_s_mem());
    if (bio_out == NULL) {
        *errorMsg = fatal("decryptMessage BIO_new", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_out);
    bio_pkey = BIO_new_mem_buf(privateKey, (int)strlen(privateKey));
    if (bio_pkey == NULL) {
        *errorMsg = fatal("decryptMessage BIO_new_mem_buf", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
    BIO_push(bio_stack, bio_pkey);
 
    pkey = PEM_read_bio_PrivateKey(bio_pkey, NULL, NULL, (char *)password);
    if (pkey == NULL) {
        *errorMsg = fatal("decryptMessage PEM_read_bio_PrivateKey", __LINE__);
        BIO_free_all(bio_stack);
        return NULL;
    }
 
    if (useCMS) {
        CMS_ContentInfo* cms = PEM_read_bio_CMS(bio_in, NULL, 0, NULL);
        if (cms == NULL) {
            *errorMsg = fatal("decryptMessage PEM_read_bio_CMS", __LINE__);
            BIO_free_all(bio_stack);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        if (!CMS_decrypt(cms, pkey, NULL, NULL, bio_out, 0)) {
            *errorMsg = fatal("decryptMessage CMS_decrypt", __LINE__);
            BIO_free_all(bio_stack);
            EVP_PKEY_free(pkey);
            CMS_ContentInfo_free(cms);
            return NULL;
        }
        CMS_ContentInfo_free(cms);
    } else {
        PKCS7 *p7 = PEM_read_bio_PKCS7(bio_in, NULL, NULL, NULL);
        if (p7 == NULL) {
            fatal("PEM_read_bio_PKCS7", __LINE__);
            BIO_free_all(bio_stack);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        if (PKCS7_decrypt(p7, pkey, NULL, bio_out, 0) != 1) {
            fatal("PKCS7_decrypt", __LINE__);
            BIO_free_all(bio_stack);
            EVP_PKEY_free(pkey);
            PKCS7_free(p7);
            return NULL;
        }
        PKCS7_free(p7);
    }
    
    char* data = bioToChar(bio_out);
    BIO_free_all(bio_stack);
    EVP_PKEY_free(pkey);
    
    return data;
}

SMIMECer parserP12(const char* p12Path, const char* password) {
    BIO* bio;
    PKCS12 *p12;
    EVP_PKEY *pri_key;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    bio = BIO_new_file(p12Path, "rb");
    SMIMECer scer;
    if(bio == NULL) {
        BIO_free(bio);
        scer.errorMsg = fatal("parserP12 BIO_new_file", __LINE__);
        return scer;
    }

    p12 = d2i_PKCS12_bio(bio, NULL);
    if(p12 == NULL) {
        BIO_free(bio);
        scer.errorMsg = fatal("parserP12 d2i_PKCS12_bio", __LINE__);
        return scer;
    }

    /* Now p12 is your PKCS12 object converted from the BIO */
    
    if (!PKCS12_parse(p12, password, &pri_key, &cert, &ca)) {
        BIO_free(bio);
        PKCS12_free(p12);
        scer.errorMsg = fatal("parserP12 PKCS12_parse", __LINE__);
        return scer;
    }

    BIO_free(bio);
    PKCS12_free(p12);
    
    scer = getX509Info(cert);
    
    EVP_PKEY *pub_key = X509_get_pubkey(cert);
    if (pub_key == NULL) {
        scer.errorMsg = fatal("parserP12 X509_get_pubkey", __LINE__);
        return scer;
    }
    
    BIO *pub_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(pub_bio, pub_key)) {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(pri_key);
        BIO_free(pub_bio);
        scer.errorMsg = fatal("parserP12 PEM_write_bio_PUBKEY", __LINE__);
        return scer;
    }
    scer.cer = bioToChar(pub_bio);
    EVP_PKEY_free(pub_key);
    BIO_free(pub_bio);
    
    BIO *pri_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(pri_bio, pri_key, NULL, NULL, 0, 0, NULL)) {
        BIO_free(pri_bio);
        EVP_PKEY_free(pri_key);
        scer.errorMsg = fatal("parserP12 PEM_write_bio_PrivateKey", __LINE__);
        return scer;
    }
    scer.key = bioToChar(pri_bio);
    
    BIO_free(pri_bio);
    EVP_PKEY_free(pri_key);
    
    return scer;
}

char* getPriKeyFromP12(const void *buf, int len, char** errorMsg) {
    BIO *buf_bio = BIO_new_mem_buf(buf, len);
    if (buf_bio == NULL) {
        return NULL;
    }
    EVP_PKEY *pKey = d2i_PrivateKey_bio(buf_bio, NULL);
    if (pKey == NULL) {
        *errorMsg = fatal("getPriKeyFromP12 d2i_PrivateKey_bio", __LINE__);
        BIO_free(buf_bio);
        return NULL;
    }
    BIO *pri_bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(pri_bio, pKey, NULL, NULL, 0, 0, NULL)) {
        *errorMsg = fatal("getPriKeyFromP12 PEM_write_bio_PrivateKey", __LINE__);
        BIO_free(buf_bio);
        BIO_free(pri_bio);
        EVP_PKEY_free(pKey);
        return NULL;
    }
    char* data = bioToChar(pri_bio);
    
    BIO_free(buf_bio);
    BIO_free(pri_bio);
    EVP_PKEY_free(pKey);
    return data;
}
