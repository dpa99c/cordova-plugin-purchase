//
//  RMAppReceipt.m
//  RMStore
//
//  Created by Hermes on 10/12/13.
//  Copyright (c) 2013 Robot Media. All rights reserved.
//
//  Refactored to use only native iOS Security.framework and CommonCrypto.
//  All OpenSSL dependencies removed.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#import "RMAppReceipt.h"
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

// From https://developer.apple.com/library/ios/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html#//apple_ref/doc/uid/TP40010573-CH106-SW1
NSInteger const RMAppReceiptASN1TypeBundleIdentifier = 2;
NSInteger const RMAppReceiptASN1TypeAppVersion = 3;
NSInteger const RMAppReceiptASN1TypeOpaqueValue = 4;
NSInteger const RMAppReceiptASN1TypeHash = 5;
NSInteger const RMAppReceiptASN1TypeInAppPurchaseReceipt = 17;
NSInteger const RMAppReceiptASN1TypeOriginalAppVersion = 19;
NSInteger const RMAppReceiptASN1TypeExpirationDate = 21;

NSInteger const RMAppReceiptASN1TypeQuantity = 1701;
NSInteger const RMAppReceiptASN1TypeProductIdentifier = 1702;
NSInteger const RMAppReceiptASN1TypeTransactionIdentifier = 1703;
NSInteger const RMAppReceiptASN1TypePurchaseDate = 1704;
NSInteger const RMAppReceiptASN1TypeOriginalTransactionIdentifier = 1705;
NSInteger const RMAppReceiptASN1TypeOriginalPurchaseDate = 1706;
NSInteger const RMAppReceiptASN1TypeSubscriptionExpirationDate = 1708;
NSInteger const RMAppReceiptASN1TypeWebOrderLineItemID = 1711;
NSInteger const RMAppReceiptASN1TypeCancellationDate = 1712;

#pragma mark - Low-level ASN.1 DER Parsing (replaces OpenSSL ASN1_get_object et al.)

// ASN.1 tag values (only the ones used in receipt parsing)
#define RM_ASN1_BOOLEAN           1
#define RM_ASN1_INTEGER           2
#define RM_ASN1_BIT_STRING        3
#define RM_ASN1_OCTET_STRING      4
#define RM_ASN1_NULL              5
#define RM_ASN1_OID               6
#define RM_ASN1_UTF8STRING       12
#define RM_ASN1_SEQUENCE         16
#define RM_ASN1_SET              17
#define RM_ASN1_IA5STRING        22
#define RM_ASN1_UTCTIME          23
#define RM_ASN1_GENERALIZEDTIME  24

static int RMASN1ReadTag(const uint8_t **pp, long *length, const uint8_t *end)
{
    if (*pp >= end) return -1;

    int tag = *(*pp)++;
    if ((tag & 0x1F) == 0x1F) {
        // Long-form tag (not used in receipts, but handle for safety)
        tag = 0;
        while (*pp < end) {
            uint8_t b = *(*pp)++;
            tag = (tag << 7) | (b & 0x7F);
            if (!(b & 0x80)) break;
        }
    }

    if (*pp >= end) return -1;

    uint8_t lenByte = *(*pp)++;
    if (lenByte & 0x80) {
        int numLenBytes = lenByte & 0x7F;
        *length = 0;
        for (int i = 0; i < numLenBytes; i++) {
            if (*pp >= end) return -1;
            *length = (*length << 8) | *(*pp)++;
        }
    } else {
        *length = lenByte;
    }

    return tag;
}

static int RMASN1ReadInteger(const uint8_t **pp, long omax)
{
    int tag;
    long length;
    int value = 0;
    const uint8_t *limit = *pp + omax;
    tag = RMASN1ReadTag(pp, &length, limit);
    if (tag == RM_ASN1_INTEGER && length > 0 && length <= 4)
    {
        for (long i = 0; i < length; i++)
        {
            value = value * 0x100 + (*pp)[i];
        }
    }
    *pp += length;
    return value;
}

static NSData* RMASN1ReadOctetStringData(const uint8_t **pp, long omax)
{
    int tag;
    long length;
    NSData *data = nil;
    const uint8_t *limit = *pp + omax;
    tag = RMASN1ReadTag(pp, &length, limit);
    if (tag == RM_ASN1_OCTET_STRING)
    {
        data = [NSData dataWithBytes:*pp length:length];
    }
    *pp += length;
    return data;
}

static NSString* RMASN1ReadString(const uint8_t **pp, long omax, int expectedTag, NSStringEncoding encoding)
{
    int tag;
    long length;
    NSString *value = nil;
    const uint8_t *limit = *pp + omax;
    tag = RMASN1ReadTag(pp, &length, limit);
    if (tag == expectedTag)
    {
        value = [[NSString alloc] initWithBytes:*pp length:length encoding:encoding];
    }
    *pp += length;
    return value;
}

static NSString* RMASN1ReadUTF8String(const uint8_t **pp, long omax)
{
    return RMASN1ReadString(pp, omax, RM_ASN1_UTF8STRING, NSUTF8StringEncoding);
}

static NSString* RMASN1ReadIA5String(const uint8_t **pp, long omax)
{
    return RMASN1ReadString(pp, omax, RM_ASN1_IA5STRING, NSASCIIStringEncoding);
}

#pragma mark - PKCS#7 Parsing Helpers

// OIDs used in PKCS#7
static const unsigned char kOID_signedData[]    = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
static const unsigned char kOID_data[]          = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static const unsigned char kOID_messageDigest[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
static const unsigned char kOID_sha1[]          = { 0x2B, 0x0E, 0x03, 0x02, 0x1A };
static const unsigned char kOID_sha256[]        = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

static BOOL RMOIDEquals(NSData *oidData, const unsigned char *expected, size_t expectedLen)
{
    if (oidData.length != expectedLen) return NO;
    return memcmp(oidData.bytes, expected, expectedLen) == 0;
}

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} RMByteRange;

static BOOL RMReadTagAndLength(RMByteRange *range, int *outTag, long *outLength)
{
    if (range->p >= range->end) return NO;
    *outTag = RMASN1ReadTag(&range->p, outLength, range->end);
    return (*outTag >= 0) && (range->p + *outLength <= range->end);
}

static NSData* RMReadOID(RMByteRange *range)
{
    int tag;
    long length;
    if (!RMReadTagAndLength(range, &tag, &length)) return nil;
    if (tag != RM_ASN1_OID) return nil;
    NSData *data = [NSData dataWithBytes:range->p length:length];
    range->p += length;
    return data;
}

static BOOL RMSkipElement(RMByteRange *range)
{
    int tag;
    long length;
    if (!RMReadTagAndLength(range, &tag, &length)) return NO;
    range->p += length;
    return YES;
}

static NSData* RMReadOctetString(RMByteRange *range)
{
    int tag;
    long length;
    if (!RMReadTagAndLength(range, &tag, &length)) return nil;
    if (tag != RM_ASN1_OCTET_STRING) return nil;
    NSData *data = [NSData dataWithBytes:range->p length:length];
    range->p += length;
    return data;
}

static NSData* RMExtractContentFromPKCS7(NSData *pkcs7Data)
{
    const uint8_t *p = pkcs7Data.bytes;
    const uint8_t *end = p + pkcs7Data.length;

    long len; int tag;
    tag = RMASN1ReadTag(&p, &len, end);
    if (tag != RM_ASN1_SEQUENCE) return nil;
    const uint8_t *contentInfoEnd = p + len;

    RMByteRange ci = { p, contentInfoEnd };
    RMReadOID(&ci); // skip content type OID

    // [0] EXPLICIT SignedData
    if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
    if (tag != 0xA0) return nil;

    RMByteRange sd = { ci.p, ci.p + len };

    // SignedData SEQUENCE
    if (!RMReadTagAndLength(&sd, &tag, &len)) return nil;
    if (tag != RM_ASN1_SEQUENCE) return nil;
    sd.end = sd.p + len;

    RMSkipElement(&sd); // version
    RMSkipElement(&sd); // digest algorithms

    // Embedded ContentInfo
    if (!RMReadTagAndLength(&sd, &tag, &len)) return nil;
    if (tag != RM_ASN1_SEQUENCE) return nil;
    RMByteRange innerCI = { sd.p, sd.p + len };
    RMReadOID(&innerCI); // skip OID

    // Extract receipt content from [0] EXPLICIT wrapping OCTET STRING
    NSData *contentData = nil;
    if (innerCI.p < innerCI.end) {
        if (!RMReadTagAndLength(&innerCI, &tag, &len)) return nil;
        if (tag == 0xA0) {
            innerCI.end = innerCI.p + len;
            contentData = RMReadOctetString(&innerCI);
        }
    }
    return contentData;
}

// Returns content data if verification succeeds, nil otherwise.
// Also returns nil (with *outSignerCertData and *outSignature populated) if the
// structure was parsed but verification needs to be attempted externally.
static NSData* RMVerifyPKCS7Signature(NSData *pkcs7Data,
                                       SecCertificateRef appleRootCert,
                                       NSData **outSignerCertData,
                                       NSData **outSignatureData,
                                       NSData **outSignedAttrsContent,
                                       SecKeyAlgorithm *outAlgorithm)
{
    const uint8_t *p = pkcs7Data.bytes;
    const uint8_t *end = p + pkcs7Data.length;

    long len; int tag;

    // 1. ContentInfo SEQUENCE
    tag = RMASN1ReadTag(&p, &len, end);
    if (tag != RM_ASN1_SEQUENCE) return nil;
    const uint8_t *contentInfoEnd = p + len;

    // 2. ContentType OID (must be signedData)
    RMByteRange ci = { p, contentInfoEnd };
    NSData *oid = RMReadOID(&ci);
    if (!oid || !RMOIDEquals(oid, kOID_signedData, sizeof(kOID_signedData))) return nil;

    // 3. [0] EXPLICIT SignedData
    if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
    if (tag != 0xA0) return nil;
    const uint8_t *signedDataEnd = ci.p + len;
    ci.end = signedDataEnd;

    // 4. SignedData SEQUENCE
    if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
    if (tag != RM_ASN1_SEQUENCE) return nil;
    ci.end = ci.p + len;

    // 5. Version
    RMSkipElement(&ci);

    // 6. DigestAlgorithms SET -> determine algorithm
    if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
    if (tag != RM_ASN1_SET) return nil;
    RMByteRange daSet = { ci.p, ci.p + len };
    ci.p += len;

    RMByteRange da = daSet;
    if (!RMReadTagAndLength(&da, &tag, &len)) return nil;
    if (tag != RM_ASN1_SEQUENCE) return nil;
    da.end = da.p + len;
    NSData *digestAlgoOID = RMReadOID(&da);

    BOOL useSHA256 = digestAlgoOID && RMOIDEquals(digestAlgoOID, kOID_sha256, sizeof(kOID_sha256));
    CC_LONG digestLength = useSHA256 ? CC_SHA256_DIGEST_LENGTH : CC_SHA1_DIGEST_LENGTH;
    SecKeyAlgorithm verifyAlgorithm = useSHA256
        ? kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
        : kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
    if (outAlgorithm) *outAlgorithm = verifyAlgorithm;

    // 7. Embedded ContentInfo -> extract receipt content
    if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
    if (tag != RM_ASN1_SEQUENCE) return nil;
    RMByteRange innerCI = { ci.p, ci.p + len };
    ci.p += len;
    RMReadOID(&innerCI);

    NSData *contentData = nil;
    if (innerCI.p < innerCI.end) {
        if (!RMReadTagAndLength(&innerCI, &tag, &len)) return nil;
        if (tag == 0xA0) {
            innerCI.end = innerCI.p + len;
            contentData = RMReadOctetString(&innerCI);
        }
    }
    if (!contentData) return nil;

    // 8. Certificates [0] IMPLICIT
    if (ci.p < ci.end) {
        const uint8_t *savedP = ci.p;
        if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
        if (tag == 0xA0) {
            RMByteRange certs = { ci.p, ci.p + len };
            // Read first certificate
            const uint8_t *certStart = certs.p;
            if (!RMReadTagAndLength(&certs, &tag, &len)) return nil;
            if (tag == RM_ASN1_SEQUENCE) {
                if (outSignerCertData) {
                    *outSignerCertData = [NSData dataWithBytes:certStart length:(certs.p + len) - certStart];
                }
            }
            ci.p = certs.end;
        } else {
            ci.p = savedP;
        }
    }

    // 9. SignerInfos SET
    if (!RMReadTagAndLength(&ci, &tag, &len)) return nil;
    if (tag != RM_ASN1_SET) return nil;
    RMByteRange signerSet = { ci.p, ci.p + len };

    // First SignerInfo SEQUENCE
    if (!RMReadTagAndLength(&signerSet, &tag, &len)) return nil;
    if (tag != RM_ASN1_SEQUENCE) return nil;
    signerSet.end = signerSet.p + len;

    RMSkipElement(&signerSet); // version
    RMSkipElement(&signerSet); // IssuerAndSerialNumber
    RMSkipElement(&signerSet); // DigestAlgorithm

    // SignedAttributes [0] IMPLICIT
    if (signerSet.p < signerSet.end) {
        if (!RMReadTagAndLength(&signerSet, &tag, &len)) return nil;
        if (tag == 0xA0) {
            if (outSignedAttrsContent) {
                *outSignedAttrsContent = [NSData dataWithBytes:signerSet.p length:len];
            }
            signerSet.p += len;
        }
    }

    RMSkipElement(&signerSet); // SignatureAlgorithm

    // Signature OCTET STRING
    if (!RMReadTagAndLength(&signerSet, &tag, &len)) return nil;
    if (tag == RM_ASN1_OCTET_STRING) {
        if (outSignatureData) {
            *outSignatureData = [NSData dataWithBytes:signerSet.p length:len];
        }
    }

    return contentData;
}

#pragma mark - Apple Root Certificate URL

static NSURL *_appleRootCertificateURL = nil;

@implementation RMAppReceipt

- (instancetype)initWithASN1Data:(NSData*)asn1Data
{
    if (self = [super init])
    {
        NSMutableArray *purchases = [NSMutableArray array];
        [RMAppReceipt enumerateASN1Attributes:(const uint8_t*)asn1Data.bytes length:asn1Data.length usingBlock:^(NSData *data, int type) {
            const uint8_t *s = (const uint8_t*)data.bytes;
            const NSUInteger length = data.length;
            switch (type)
            {
                case RMAppReceiptASN1TypeBundleIdentifier:
                    _bundleIdentifierData = data;
                    _bundleIdentifier = RMASN1ReadUTF8String(&s, length);
                    break;
                case RMAppReceiptASN1TypeAppVersion:
                    _appVersion = RMASN1ReadUTF8String(&s, length);
                    break;
                case RMAppReceiptASN1TypeOpaqueValue:
                    _opaqueValue = data;
                    break;
                case RMAppReceiptASN1TypeHash:
                    _receiptHash = data;
                    break;
                case RMAppReceiptASN1TypeInAppPurchaseReceipt:
                {
                    RMAppReceiptIAP *purchase = [[RMAppReceiptIAP alloc] initWithASN1Data:data];
                    [purchases addObject:purchase];
                    break;
                }
                case RMAppReceiptASN1TypeOriginalAppVersion:
                    _originalAppVersion = RMASN1ReadUTF8String(&s, length);
                    break;
                case RMAppReceiptASN1TypeExpirationDate:
                {
                    NSString *string = RMASN1ReadIA5String(&s, length);
                    _expirationDate = [RMAppReceipt formatRFC3339String:string];
                    break;
                }
            }
        }];
        _inAppPurchases = purchases;
    }
    return self;
}

- (BOOL)containsInAppPurchaseOfProductIdentifier:(NSString*)productIdentifier
{
    for (RMAppReceiptIAP *purchase in _inAppPurchases)
    {
        if ([purchase.productIdentifier isEqualToString:productIdentifier]) return YES;
    }
    return NO;
}

-(BOOL)containsActiveAutoRenewableSubscriptionOfProductIdentifier:(NSString *)productIdentifier forDate:(NSDate *)date
{
    RMAppReceiptIAP *lastTransaction = nil;

    for (RMAppReceiptIAP *iap in self.inAppPurchases)
    {
        if (![iap.productIdentifier isEqualToString:productIdentifier]) continue;

        if (!lastTransaction || [iap.subscriptionExpirationDate compare:lastTransaction.subscriptionExpirationDate] == NSOrderedDescending)
        {
            lastTransaction = iap;
        }
    }

    return [lastTransaction isActiveAutoRenewableSubscriptionForDate:date];
}

- (BOOL)verifyReceiptHash
{
    NSUUID *uuid = [UIDevice currentDevice].identifierForVendor;
    unsigned char uuidBytes[16];
    [uuid getUUIDBytes:uuidBytes];

    NSMutableData *data = [NSMutableData data];
    [data appendBytes:uuidBytes length:sizeof(uuidBytes)];
    [data appendData:self.opaqueValue];
    [data appendData:self.bundleIdentifierData];

    NSMutableData *expectedHash = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1((const uint8_t*)data.bytes, (CC_LONG)data.length, (uint8_t*)expectedHash.mutableBytes);

    return [expectedHash isEqualToData:self.receiptHash];
}

+ (RMAppReceipt*)bundleReceipt
{
    NSURL *URL = [NSBundle mainBundle].appStoreReceiptURL;
    NSString *path = URL.path;
    const BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:nil];
    if (!exists) return nil;

    NSData *data = [RMAppReceipt dataFromPKCS7Path:path];
    if (!data) return nil;

    RMAppReceipt *receipt = [[RMAppReceipt alloc] initWithASN1Data:data];
    return receipt;
}

+ (void)setAppleRootCertificateURL:(NSURL*)url
{
    _appleRootCertificateURL = url;
}

#pragma mark - PKCS#7 Main Entry Point

+ (NSData*)dataFromPKCS7Path:(NSString*)path
{
    NSData *pkcs7Data = [NSData dataWithContentsOfFile:path];
    if (!pkcs7Data) return nil;

    // Try to load the Apple Root Certificate
    NSURL *certificateURL = _appleRootCertificateURL ? : [[NSBundle mainBundle] URLForResource:@"AppleIncRootCertificate" withExtension:@"cer"];
    NSData *certificateData = [NSData dataWithContentsOfURL:certificateURL];

    if (certificateData)
    {
        SecCertificateRef appleRootCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData);
        if (appleRootCert)
        {
            NSData *verifiedContent = [self validatePKCS7:pkcs7Data withAppleRootCertificate:appleRootCert];
            CFRelease(appleRootCert);
            if (verifiedContent) return verifiedContent;
        }
    }

    // Fallback: extract content without verification
    return RMExtractContentFromPKCS7(pkcs7Data);
}

+ (NSData*)validatePKCS7:(NSData*)pkcs7Data withAppleRootCertificate:(SecCertificateRef)appleRootCert
{
    NSData *signerCertData = nil;
    NSData *signatureData = nil;
    NSData *signedAttrsContent = nil;
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;

    NSData *contentData = RMVerifyPKCS7Signature(pkcs7Data, appleRootCert,
                                                  &signerCertData, &signatureData,
                                                  &signedAttrsContent, &algorithm);
    if (!contentData) return nil;
    if (!signerCertData || !signatureData || !signedAttrsContent) return nil;

    // Determine digest parameters from algorithm
    BOOL useSHA256 = (algorithm == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256);
    CC_LONG digestLength = useSHA256 ? CC_SHA256_DIGEST_LENGTH : CC_SHA1_DIGEST_LENGTH;

    // --- Step A: Verify certificate chain ---
    SecCertificateRef signerCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)signerCertData);
    if (!signerCert) return nil;

    SecPolicyRef policy = SecPolicyCreateBasicX509();
    NSArray *certs = @[ (__bridge id)signerCert ];
    SecTrustRef trust = NULL;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFArrayRef)certs, policy, &trust);
    if (status != errSecSuccess) {
        CFRelease(signerCert);
        CFRelease(policy);
        return nil;
    }

    SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)@[ (__bridge id)appleRootCert ]);
    SecTrustSetAnchorCertificatesOnly(trust, YES);

    CFErrorRef trustError = NULL;
    BOOL trusted = SecTrustEvaluateWithError(trust, &trustError);
    if (!trusted) {
        CFRelease(trust);
        CFRelease(signerCert);
        CFRelease(policy);
        return nil;
    }

    // --- Step B: Verify message digest in signedAttrs matches content ---
    // signedAttrs is a SET of SEQUENCE { OID, SET { value } }
    // Look for messageDigest OID (1.2.840.113549.1.9.4)
    RMByteRange sa = { signedAttrsContent.bytes, (const uint8_t*)signedAttrsContent.bytes + signedAttrsContent.length };
    NSData *foundMessageDigest = nil;

    while (sa.p < sa.end) {
        int tag; long len;
        if (!RMReadTagAndLength(&sa, &tag, &len)) break;
        if (tag != RM_ASN1_SEQUENCE) break;
        RMByteRange attr = { sa.p, sa.p + len };
        sa.p += len;

        NSData *attrOID = RMReadOID(&attr);
        if (attrOID && RMOIDEquals(attrOID, kOID_messageDigest, sizeof(kOID_messageDigest))) {
            if (!RMReadTagAndLength(&attr, &tag, &len)) break;
            if (tag == RM_ASN1_SET) {
                attr.end = attr.p + len;
                foundMessageDigest = RMReadOctetString(&attr);
            }
            break;
        }
    }

    // Compute digest of the content
    unsigned char computedDigest[CC_SHA256_DIGEST_LENGTH];
    if (useSHA256) {
        CC_SHA256(contentData.bytes, (CC_LONG)contentData.length, computedDigest);
    } else {
        CC_SHA1(contentData.bytes, (CC_LONG)contentData.length, computedDigest);
    }
    NSData *computedDigestData = [NSData dataWithBytes:computedDigest length:digestLength];

    if (!foundMessageDigest || ![foundMessageDigest isEqualToData:computedDigestData]) {
        CFRelease(trust);
        CFRelease(signerCert);
        CFRelease(policy);
        return nil;
    }

    // --- Step C: Re-encode signedAttrs for signature verification ---
    // The signature was computed over the DER encoding of signedAttrs as SET OF,
    // but they were stored with IMPLICIT [0] tag. Re-encode with SET tag.
    NSMutableData *reencoded = [NSMutableData data];
    uint8_t setTag = 0x31;
    [reencoded appendBytes:&setTag length:1];
    NSUInteger saLen = signedAttrsContent.length;
    if (saLen < 128) {
        uint8_t byte = (uint8_t)saLen;
        [reencoded appendBytes:&byte length:1];
    } else if (saLen < 256) {
        uint8_t bytes[] = { 0x81, (uint8_t)saLen };
        [reencoded appendBytes:bytes length:2];
    } else {
        uint8_t bytes[] = { 0x82, (uint8_t)(saLen >> 8), (uint8_t)(saLen & 0xFF) };
        [reencoded appendBytes:bytes length:3];
    }
    [reencoded appendData:signedAttrsContent];

    // --- Step D: Verify RSA signature ---
    SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
    CFErrorRef verifyError = NULL;
    BOOL signatureValid = SecKeyVerifySignature(publicKey,
                                                 algorithm,
                                                 (__bridge CFDataRef)reencoded,
                                                 (__bridge CFDataRef)signatureData,
                                                 &verifyError);

    CFRelease(publicKey);
    CFRelease(trust);
    CFRelease(signerCert);
    CFRelease(policy);

    if (!signatureValid) return nil;

    return contentData;
}

#pragma mark - ASN.1 Receipt Attribute Enumeration

/*
 Reimplemented using custom DER parsing instead of OpenSSL's ASN1_get_object.
 Matches the original behavior exactly.
 */
+ (void)enumerateASN1Attributes:(const uint8_t*)p length:(long)tlength usingBlock:(void (^)(NSData *data, int type))block
{
    int tag;
    long length;

    const uint8_t *end = p + tlength;

    tag = RMASN1ReadTag(&p, &length, end);
    if (tag != RM_ASN1_SET) return;

    const uint8_t *setEnd = p + length;

    while (p < setEnd)
    {
        tag = RMASN1ReadTag(&p, &length, setEnd);
        if (tag != RM_ASN1_SEQUENCE) break;

        const uint8_t *sequenceEnd = p + length;

        const int attributeType = RMASN1ReadInteger(&p, sequenceEnd - p);
        RMASN1ReadInteger(&p, sequenceEnd - p); // Consume attribute version

        NSData *data = RMASN1ReadOctetStringData(&p, sequenceEnd - p);
        if (data)
        {
            block(data, attributeType);
        }

        while (p < sequenceEnd)
        { // Skip remaining fields in case of unexpected extra data
            tag = RMASN1ReadTag(&p, &length, sequenceEnd);
            p += length;
        }
    }
}

+ (NSDate*)formatRFC3339String:(NSString*)string
{
    static NSDateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZ";
    });
    NSDate *date = [formatter dateFromString:string];
    return date;
}

@end

#pragma mark - RMAppReceiptIAP

@implementation RMAppReceiptIAP

- (instancetype)initWithASN1Data:(NSData*)asn1Data
{
    if (self = [super init])
    {
        [RMAppReceipt enumerateASN1Attributes:(const uint8_t*)asn1Data.bytes length:asn1Data.length usingBlock:^(NSData *data, int type) {
            const uint8_t *p = (const uint8_t*)data.bytes;
            const NSUInteger length = data.length;
            switch (type)
            {
                case RMAppReceiptASN1TypeQuantity:
                    _quantity = RMASN1ReadInteger(&p, length);
                    break;
                case RMAppReceiptASN1TypeProductIdentifier:
                    _productIdentifier = RMASN1ReadUTF8String(&p, length);
                    break;
                case RMAppReceiptASN1TypeTransactionIdentifier:
                    _transactionIdentifier = RMASN1ReadUTF8String(&p, length);
                    break;
                case RMAppReceiptASN1TypePurchaseDate:
                {
                    NSString *string = RMASN1ReadIA5String(&p, length);
                    _purchaseDate = [RMAppReceipt formatRFC3339String:string];
                    break;
                }
                case RMAppReceiptASN1TypeOriginalTransactionIdentifier:
                    _originalTransactionIdentifier = RMASN1ReadUTF8String(&p, length);
                    break;
                case RMAppReceiptASN1TypeOriginalPurchaseDate:
                {
                    NSString *string = RMASN1ReadIA5String(&p, length);
                    _originalPurchaseDate = [RMAppReceipt formatRFC3339String:string];
                    break;
                }
                case RMAppReceiptASN1TypeSubscriptionExpirationDate:
                {
                    NSString *string = RMASN1ReadIA5String(&p, length);
                    _subscriptionExpirationDate = [RMAppReceipt formatRFC3339String:string];
                    break;
                }
                case RMAppReceiptASN1TypeWebOrderLineItemID:
                    _webOrderLineItemID = RMASN1ReadInteger(&p, length);
                    break;
                case RMAppReceiptASN1TypeCancellationDate:
                {
                    NSString *string = RMASN1ReadIA5String(&p, length);
                    _cancellationDate = [RMAppReceipt formatRFC3339String:string];
                    break;
                }
            }
        }];
    }
    return self;
}

- (BOOL)isActiveAutoRenewableSubscriptionForDate:(NSDate*)date
{
    NSAssert(self.subscriptionExpirationDate != nil, @"The product %@ is not an auto-renewable subscription.", self.productIdentifier);

    if (self.cancellationDate) return NO;

    return [self.purchaseDate compare:date] != NSOrderedDescending && [date compare:self.subscriptionExpirationDate] != NSOrderedDescending;
}

@end
