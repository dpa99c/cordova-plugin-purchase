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
#import "Logger.h"

@interface RMAppReceipt ()
+ (NSData*)dataFromPKCS7Data:(NSData*)pkcs7Data;
+ (NSData*)validatePKCS7:(NSData*)pkcs7Data withAppleRootCertificate:(SecCertificateRef)appleRootCert;
@end

// Enable for detailed PKCS#7 parsing logs
#define RM_PKCS7_DEBUG 0

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
#define RM_ASN1_SEQUENCE         0x30
#define RM_ASN1_SET              0x31
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
    if (range->p >= range->end) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] RMReadTagAndLength: p >= end"];
#endif
        return NO;
    }
    *outTag = RMASN1ReadTag(&range->p, outLength, range->end);
    if (*outTag < 0) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] RMReadTagAndLength: failed to read tag"];
#endif
        return NO;
    }
    if (range->p + *outLength > range->end) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] RMReadTagAndLength: content overflow (p+%ld > end, diff=%ld)", *outLength, (long)(range->p + *outLength - range->end)];
#endif
        return NO;
    }
    return YES;
}

static NSData* RMReadOID(RMByteRange *range)
{
    int tag;
    long length;
    if (!RMReadTagAndLength(range, &tag, &length)) return nil;
    if (tag != RM_ASN1_OID) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] RMReadOID: expected OID (0x06) got tag=0x%02X", tag];
#endif
        return nil;
    }
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
    if (tag != RM_ASN1_OCTET_STRING) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] RMReadOctetString: expected OCTET STRING (0x04) got tag=0x%02X", tag];
#endif
        return nil;
    }
    NSData *data = [NSData dataWithBytes:range->p length:length];
    range->p += length;
    return data;
}

#pragma mark - PKCS#7 Content Extraction (fallback without verification)

static NSData* RMExtractContentFromPKCS7(NSData *pkcs7Data)
{
    const uint8_t *p = pkcs7Data.bytes;
    const uint8_t *end = p + pkcs7Data.length;

#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] RMExtractContentFromPKCS7: data length=%lu", (unsigned long)pkcs7Data.length];
#endif

    long len; int tag;

    // 1. Outer ContentInfo SEQUENCE
    tag = RMASN1ReadTag(&p, &len, end);
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 1: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    const uint8_t *contentInfoEnd = p + len;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 1 OK: ContentInfo SEQUENCE len=%ld", len];
#endif

    // 2. ContentType OID
    RMByteRange ci = { p, contentInfoEnd };
    NSData *oid = RMReadOID(&ci);
    if (!oid) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 2: could not read OID"];
#endif
        return nil;
    }
    if (!RMOIDEquals(oid, kOID_signedData, sizeof(kOID_signedData))) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 2: OID is not signedData"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 2 OK: OID = signedData"];
#endif

    // 3. [0] EXPLICIT SignedData
    if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 3: cannot read [0] EXPLICIT"];
#endif
        return nil;
    }
    if (tag != 0xA0) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 3: expected [0] (0xA0), got tag=0x%02X", tag];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 3 OK: [0] EXPLICIT len=%ld", len];
#endif

    RMByteRange sd = { ci.p, ci.p + len };

    // 4. SignedData SEQUENCE
    if (!RMReadTagAndLength(&sd, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 4: cannot read SignedData SEQUENCE"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 4: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    sd.end = sd.p + len;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 4 OK: SignedData SEQUENCE len=%ld", len];
#endif

    // 5. Version
    if (!RMSkipElement(&sd)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 5: cannot skip version"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 5 OK: version skipped, remaining=%ld", (long)(sd.end - sd.p)];
#endif

    // 6. DigestAlgorithms SET (skip entirely)
    if (!RMSkipElement(&sd)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 6: cannot skip DigestAlgorithms SET"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 6 OK: digest algorithms skipped, remaining=%ld", (long)(sd.end - sd.p)];
#endif

    // 7. Embedded ContentInfo SEQUENCE
    if (!RMReadTagAndLength(&sd, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 7: cannot read inner ContentInfo SEQUENCE"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 7: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    RMByteRange innerCI = { sd.p, sd.p + len };
    sd.p += len;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] Step 7 OK: inner ContentInfo SEQUENCE len=%ld", len];
#endif

    // 8. Inner ContentType OID (should be "data")
    oid = RMReadOID(&innerCI);
    if (!oid) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 8: could not read inner OID"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    {
        const uint8_t *ob = oid.bytes;
        NSMutableString *hs = [NSMutableString string];
        for (NSUInteger i = 0; i < oid.length; i++) [hs appendFormat:@"%02x ", ob[i]];
        [Logger debug:@"[RMReceipt] Step 8 OK: inner OID = %@", hs];
    }
#endif

    // 9. Extract receipt content from inner ContentInfo
    // The content is: [0] EXPLICIT OCTET STRING  (per PKCS#7 ContentInfo definition)
    NSData *contentData = nil;
    if (innerCI.p < innerCI.end) {
        if (!RMReadTagAndLength(&innerCI, &tag, &len)) {
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] FAIL step 9: cannot read content wrapper tag"];
#endif
            return nil;
        }
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] Step 9: content wrapper tag=0x%02X len=%ld", tag, len];
#endif
        if (tag == 0xA0 || tag == 0x80) {
            // [0] EXPLICIT or [0] PRIMITIVE wrapper (PKCS#7 standard)
            innerCI.end = innerCI.p + len;
            contentData = RMReadOctetString(&innerCI);
        } else if (tag == RM_ASN1_OCTET_STRING) {
            // Direct OCTET STRING (no wrapper - some implementations omit the [0] tag)
            contentData = [NSData dataWithBytes:innerCI.p length:len];
            innerCI.p += len;
        }
    }

    if (!contentData) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] FAIL step 9: could not extract content data"];
#endif
        return nil;
    }

#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] RMExtractContentFromPKCS7 SUCCESS: content len=%lu", (unsigned long)contentData.length];
#endif
    return contentData;
}

#pragma mark - PKCS#7 Parsing + Signature Verification

static NSData* RMVerifyPKCS7Signature(NSData *pkcs7Data,
                                       SecCertificateRef appleRootCert,
                                       NSData **outSignerCertData,
                                       NSData **outSignatureData,
                                       NSData **outSignedAttrsContent,
                                       SecKeyAlgorithm *outAlgorithm)
{
    const uint8_t *p = pkcs7Data.bytes;
    const uint8_t *end = p + pkcs7Data.length;

#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] RMVerifyPKCS7Signature: data length=%lu", (unsigned long)pkcs7Data.length];
#endif

    long len; int tag;

    // 1. ContentInfo SEQUENCE
    tag = RMASN1ReadTag(&p, &len, end);
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 1: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    const uint8_t *contentInfoEnd = p + len;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 1 OK: ContentInfo SEQUENCE len=%ld", len];
#endif

    // 2. ContentType OID (must be signedData)
    RMByteRange ci = { p, contentInfoEnd };
    NSData *oid = RMReadOID(&ci);
    if (!oid || !RMOIDEquals(oid, kOID_signedData, sizeof(kOID_signedData))) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 2: OID mismatch"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 2 OK: OID = signedData"];
#endif

    // 3. [0] EXPLICIT SignedData
    if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 3: cannot read [0]"];
#endif
        return nil;
    }
    if (tag != 0xA0) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 3: expected [0] (0xA0), got tag=0x%02X", tag];
#endif
        return nil;
    }
    const uint8_t *signedDataEnd = ci.p + len;
    ci.end = signedDataEnd;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 3 OK: [0] EXPLICIT len=%ld", len];
#endif

    // 4. SignedData SEQUENCE
    if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 4: cannot read SignedData SEQUENCE"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 4: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    ci.end = ci.p + len;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 4 OK: SignedData SEQUENCE len=%ld", len];
#endif

    // 5. Version
    if (!RMSkipElement(&ci)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 5: cannot skip version"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 5 OK: version skipped, remaining=%ld", (long)(ci.end - ci.p)];
#endif

    // 6. DigestAlgorithms SET -> determine algorithm
    if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 6: cannot read DigestAlgorithms SET"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SET) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 6: expected SET (0x31), got tag=0x%02X", tag];
#endif
        return nil;
    }
    RMByteRange daSet = { ci.p, ci.p + len };
    ci.p += len;

    // Read first digest algorithm OID
    RMByteRange da = daSet;
    if (!RMReadTagAndLength(&da, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 6a: cannot read DigestAlgorithm SEQUENCE"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 6a: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    da.end = da.p + len;
    NSData *digestAlgoOID = RMReadOID(&da);

    BOOL useSHA256 = digestAlgoOID && RMOIDEquals(digestAlgoOID, kOID_sha256, sizeof(kOID_sha256));
    CC_LONG digestLength = useSHA256 ? CC_SHA256_DIGEST_LENGTH : CC_SHA1_DIGEST_LENGTH;
    SecKeyAlgorithm verifyAlgorithm = useSHA256
        ? kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
        : kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
    if (outAlgorithm) *outAlgorithm = verifyAlgorithm;
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 6 OK: digest algo = %@", useSHA256 ? @"SHA256" : @"SHA1"];
#endif

    // 7. Embedded ContentInfo -> extract receipt content
    if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 7: cannot read inner ContentInfo SEQUENCE"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 7: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    RMByteRange innerCI = { ci.p, ci.p + len };
    ci.p += len;
    oid = RMReadOID(&innerCI);
#if RM_PKCS7_DEBUG
    {
        const uint8_t *ob = oid.bytes;
        NSMutableString *hs = [NSMutableString string];
        for (NSUInteger i = 0; i < oid.length; i++) [hs appendFormat:@"%02x ", ob[i]];
        [Logger debug:@"[RMReceipt] VERIFY Step 7 OK: inner ContentInfo SEQUENCE len=%ld, OID=%@", len, hs];
    }
#endif

    NSData *contentData = nil;
    if (innerCI.p < innerCI.end) {
        if (!RMReadTagAndLength(&innerCI, &tag, &len)) {
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] VERIFY FAIL step 7a: cannot read content wrapper"];
#endif
            return nil;
        }
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY Step 7a: content wrapper tag=0x%02X len=%ld", tag, len];
#endif
        if (tag == 0xA0 || tag == 0x80) {
            // [0] EXPLICIT or [0] PRIMITIVE wrapper (PKCS#7 standard)
            innerCI.end = innerCI.p + len;
            contentData = RMReadOctetString(&innerCI);
        } else if (tag == RM_ASN1_OCTET_STRING) {
            // Direct OCTET STRING (no wrapper)
            contentData = [NSData dataWithBytes:innerCI.p length:len];
            innerCI.p += len;
        }
    }
    if (!contentData) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 7b: could not extract content data"];
#endif
        return nil;
    }
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 7 OK: extracted content len=%lu", (unsigned long)contentData.length];
#endif

    // 8. Certificates [0] IMPLICIT - extract ALL certificates for chain building
    if (ci.p < ci.end) {
        const uint8_t *savedP = ci.p;
        if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] VERIFY WARNING step 8: cannot read certificates block"];
#endif
            ci.p = savedP;
        } else if (tag == 0xA0) {
            RMByteRange certs = { ci.p, ci.p + len };
            // Read ALL certificates in the block
            while (certs.p < certs.end) {
                const uint8_t *certStart = certs.p;
                int certTag; long certLen;
                if (!RMReadTagAndLength(&certs, &certTag, &certLen)) break;
                if (certTag == RM_ASN1_SEQUENCE) {
                    NSData *certData = [NSData dataWithBytes:certStart length:(certs.p + certLen) - certStart];
                    // First certificate is the signer
                    if (outSignerCertData && *outSignerCertData == nil) {
                        *outSignerCertData = certData;
                    }
#if RM_PKCS7_DEBUG
                    [Logger debug:@"[RMReceipt] VERIFY Step 8: found cert len=%lu", (unsigned long)certData.length];
#endif
                }
                certs.p += certLen;
            }
            ci.p = certs.end;
        } else {
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] VERIFY Step 8: no certificates [0] tag (tag=0x%02X), restoring position", tag];
#endif
            ci.p = savedP;
        }
    }
#if RM_PKCS7_DEBUG
    else {
        [Logger debug:@"[RMReceipt] VERIFY Step 8: no data remaining for certificates"];
    }
#endif

    // 9. SignerInfos SET
    if (!RMReadTagAndLength(&ci, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9: cannot read SignerInfos SET"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SET) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9: expected SET, got tag=0x%02X", tag];
#endif
        return nil;
    }
    RMByteRange signerSet = { ci.p, ci.p + len };
#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY Step 9 OK: SignerInfos SET len=%ld", len];
#endif

    // First SignerInfo SEQUENCE
    if (!RMReadTagAndLength(&signerSet, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9a: cannot read SignerInfo SEQUENCE"];
#endif
        return nil;
    }
    if (tag != RM_ASN1_SEQUENCE) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9a: expected SEQUENCE, got tag=0x%02X", tag];
#endif
        return nil;
    }
    signerSet.end = signerSet.p + len;

    if (!RMSkipElement(&signerSet)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9b: cannot skip SignerInfo version"];
#endif
        return nil;
    }
    if (!RMSkipElement(&signerSet)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9c: cannot skip IssuerAndSerialNumber"];
#endif
        return nil;
    }
    if (!RMSkipElement(&signerSet)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9d: cannot skip DigestAlgorithm"];
#endif
        return nil;
    }

    // SignedAttributes [0] IMPLICIT (optional in Apple's receipt SignerInfo)
    if (signerSet.p < signerSet.end) {
        const uint8_t *signedAttrsStart = signerSet.p;
        if (!RMReadTagAndLength(&signerSet, &tag, &len)) {
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] VERIFY WARNING step 9e: cannot read SignedAttributes"];
#endif
        } else if (tag == 0xA0) {
            if (outSignedAttrsContent) {
                *outSignedAttrsContent = [NSData dataWithBytes:signerSet.p length:len];
            }
            signerSet.p += len;
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] VERIFY Step 9e OK: SignedAttributes len=%ld", len];
#endif
        } else {
            // Receipts without signed attributes place SignatureAlgorithm here.
            signerSet.p = signedAttrsStart;
#if RM_PKCS7_DEBUG
            [Logger debug:@"[RMReceipt] VERIFY Step 9e: no signed attributes (next tag=0x%02X)", tag];
#endif
        }
    }

    if (!RMSkipElement(&signerSet)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9f: cannot skip SignatureAlgorithm"];
#endif
        return nil;
    }

    // Signature OCTET STRING
    if (!RMReadTagAndLength(&signerSet, &tag, &len)) {
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY FAIL step 9g: cannot read Signature"];
#endif
        return nil;
    }
    if (tag == RM_ASN1_OCTET_STRING) {
        if (outSignatureData) {
            *outSignatureData = [NSData dataWithBytes:signerSet.p length:len];
        }
#if RM_PKCS7_DEBUG
        [Logger debug:@"[RMReceipt] VERIFY Step 9g OK: Signature len=%ld", len];
#endif
    }

#if RM_PKCS7_DEBUG
    [Logger debug:@"[RMReceipt] VERIFY parsing complete, returning contentData len=%lu", (unsigned long)contentData.length];
#endif
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

    return [RMAppReceipt receiptWithPKCS7Data:[NSData dataWithContentsOfFile:path]];
}

+ (RMAppReceipt*)receiptWithPKCS7Data:(NSData*)pkcs7Data
{
    if (!pkcs7Data) return nil;
    NSData *data = [self dataFromPKCS7Data:pkcs7Data];
    if (!data) return nil;
    return [[RMAppReceipt alloc] initWithASN1Data:data];
}

+ (void)setAppleRootCertificateURL:(NSURL*)url
{
    _appleRootCertificateURL = url;
}

#pragma mark - PKCS#7 Main Entry Point

+ (NSData*)dataFromPKCS7Data:(NSData*)pkcs7Data
{
    if (!pkcs7Data) {
        [Logger error:@"Could not read PKCS#7 receipt data"];
        return nil;
    }

    [Logger debug:@"Read %lu bytes from PKCS#7 receipt data", (unsigned long)pkcs7Data.length];

    // Try to load the Apple Root Certificate
    NSURL *certificateURL = _appleRootCertificateURL ? : [[NSBundle mainBundle] URLForResource:@"AppleIncRootCertificate" withExtension:@"cer"];
    NSData *certificateData = certificateURL ? [NSData dataWithContentsOfURL:certificateURL] : nil;

    if (certificateData)
    {
        [Logger debug:@"[RMReceipt] Apple Root Certificate loaded: %lu bytes", (unsigned long)certificateData.length];
        SecCertificateRef appleRootCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData);
        if (appleRootCert)
        {
            NSData *verifiedContent = [self validatePKCS7:pkcs7Data withAppleRootCertificate:appleRootCert];
            CFRelease(appleRootCert);
            if (verifiedContent) {
                [Logger debug:@"[RMReceipt] PKCS#7 verified successfully"];
                return verifiedContent;
            }
            [Logger debug:@"[RMReceipt] PKCS#7 verification failed, falling back to extraction without verification"];
        } else {
            [Logger debug:@"[RMReceipt] Failed to create SecCertificate from Apple Root Certificate data"];
        }
    } else {
        [Logger debug:@"[RMReceipt] Apple Root Certificate not found at %@", certificateURL];
    }

    // Fallback: extract content without verification
    NSData *fallbackContent = RMExtractContentFromPKCS7(pkcs7Data);
    if (fallbackContent) {
        [Logger debug:@"[RMReceipt] Fallback extraction succeeded: %lu bytes", (unsigned long)fallbackContent.length];
    } else {
        [Logger debug:@"[RMReceipt] Fallback extraction FAILED"];
    }
    return fallbackContent;
}

+ (NSData*)validatePKCS7:(NSData*)pkcs7Data withAppleRootCertificate:(SecCertificateRef)appleRootCert
{
    [Logger debug:@"[RMReceipt] validatePKCS7: starting verification"];

    NSData *signerCertData = nil;
    NSData *signatureData = nil;
    NSData *signedAttrsContent = nil;
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;

    NSData *contentData = RMVerifyPKCS7Signature(pkcs7Data, appleRootCert,
                                                  &signerCertData, &signatureData,
                                                  &signedAttrsContent, &algorithm);
    if (!contentData) {
        [Logger debug:@"[RMReceipt] validatePKCS7: RMVerifyPKCS7Signature returned nil contentData"];
        return nil;
    }
    if (!signerCertData) {
        [Logger debug:@"[RMReceipt] validatePKCS7: no signer certificate data"];
        return nil;
    }
    if (!signatureData) {
        [Logger debug:@"[RMReceipt] validatePKCS7: no signature data"];
        return nil;
    }
    [Logger debug:@"[RMReceipt] validatePKCS7: all components extracted. cert=%lu sig=%lu attrs=%lu content=%lu",
          (unsigned long)signerCertData.length, (unsigned long)signatureData.length,
          (unsigned long)signedAttrsContent.length, (unsigned long)contentData.length];

    // Determine digest parameters from algorithm
    BOOL useSHA256 = (algorithm == kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256);
    CC_LONG digestLength = useSHA256 ? CC_SHA256_DIGEST_LENGTH : CC_SHA1_DIGEST_LENGTH;
    [Logger debug:@"[RMReceipt] validatePKCS7: using %@", useSHA256 ? @"SHA256" : @"SHA1"];

    // --- Step A: Verify certificate chain ---
    SecCertificateRef signerCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)signerCertData);
    if (!signerCert) {
        [Logger debug:@"[RMReceipt] validatePKCS7 FAIL A: could not create SecCertificate from signer cert data"];
        return nil;
    }

    CFStringRef certSummary = SecCertificateCopySubjectSummary(signerCert);
    [Logger debug:@"[RMReceipt] validatePKCS7: signer certificate subject = %@", (__bridge NSString*)certSummary];
    CFRelease(certSummary);

    // Extract ALL certificates from the PKCS#7 for chain building
    NSMutableArray *allCerts = [NSMutableArray arrayWithObject:(__bridge id)signerCert];
    {
        // Re-parse just enough to find all certificates in the [0] IMPLICIT block
        const uint8_t *cp = pkcs7Data.bytes;
        const uint8_t *ce = cp + pkcs7Data.length;
        long clen; int ctag;
        // Skip ContentInfo SEQUENCE
        ctag = RMASN1ReadTag(&cp, &clen, ce);
        if (ctag == RM_ASN1_SEQUENCE) {
            const uint8_t *ciEnd = cp + clen;
            // Skip OID
            RMByteRange cci = { cp, ciEnd };
            RMReadOID(&cci);
            // Skip [0] EXPLICIT
            if (RMReadTagAndLength(&cci, &ctag, &clen) && ctag == 0xA0) {
                RMByteRange csd = { cci.p, cci.p + clen };
                // Skip SignedData SEQUENCE
                if (RMReadTagAndLength(&csd, &ctag, &clen) && ctag == RM_ASN1_SEQUENCE) {
                    csd.end = csd.p + clen;
                    // Skip version, digest algos, inner ContentInfo
                    RMSkipElement(&csd); // version
                    RMSkipElement(&csd); // digest algos
                    // Skip inner ContentInfo
                    if (RMReadTagAndLength(&csd, &ctag, &clen) && ctag == RM_ASN1_SEQUENCE) {
                        csd.p += clen;
                    }
                    // Now at certificates [0] IMPLICIT
                    if (csd.p < csd.end) {
                        if (RMReadTagAndLength(&csd, &ctag, &clen) && ctag == 0xA0) {
                            RMByteRange certsRange = { csd.p, csd.p + clen };
                            while (certsRange.p < certsRange.end) {
                                const uint8_t *certStart = certsRange.p;
                                int certTag; long certLen;
                                if (!RMReadTagAndLength(&certsRange, &certTag, &certLen)) break;
                                if (certTag == RM_ASN1_SEQUENCE) {
                                    NSData *certData = [NSData dataWithBytes:certStart length:(certsRange.p + certLen) - certStart];
                                    // Add all certs after the first (signer) as intermediates
                                    if (allCerts.count > 0) {
                                        SecCertificateRef intermCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
                                        if (intermCert) {
                                            [allCerts addObject:(__bridge id)intermCert];
                                            CFRelease(intermCert);
                                        }
                                    }
                                }
                                certsRange.p += certLen;
                            }
                        }
                    }
                }
            }
        }
    }
    [Logger debug:@"[RMReceipt] validatePKCS7: building trust with %lu certificates", (unsigned long)allCerts.count];

    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFArrayRef)allCerts, policy, &trust);
    if (status != errSecSuccess) {
        [Logger debug:@"[RMReceipt] validatePKCS7 FAIL A: SecTrustCreateWithCertificates error %d", (int)status];
        CFRelease(signerCert);
        CFRelease(policy);
        return nil;
    }

    SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)@[ (__bridge id)appleRootCert ]);
    SecTrustSetAnchorCertificatesOnly(trust, YES);

    CFErrorRef trustError = NULL;
    BOOL trusted = SecTrustEvaluateWithError(trust, &trustError);
    if (!trusted) {
        [Logger debug:@"[RMReceipt] validatePKCS7 FAIL A: certificate trust evaluation failed: %@", trustError];
        if (trustError) CFRelease(trustError);
        CFRelease(trust);
        CFRelease(signerCert);
        CFRelease(policy);
        return nil;
    }
    [Logger debug:@"[RMReceipt] validatePKCS7 Step A OK: certificate chain trusted"];

    NSData *signaturePayload;
    if (signedAttrsContent) {
        // --- Step B: Verify message digest in signedAttrs matches content ---
        RMByteRange sa = { signedAttrsContent.bytes, (const uint8_t*)signedAttrsContent.bytes + signedAttrsContent.length };
        NSData *foundMessageDigest = nil;

        while (sa.p < sa.end) {
            int saTag; long saLen;
            if (!RMReadTagAndLength(&sa, &saTag, &saLen)) {
                [Logger debug:@"[RMReceipt] validatePKCS7 FAIL B: cannot read signedAttrs SEQUENCE at offset %ld", (long)(sa.p - (const uint8_t*)signedAttrsContent.bytes)];
                break;
            }
            if (saTag != RM_ASN1_SEQUENCE) {
                [Logger debug:@"[RMReceipt] validatePKCS7 FAIL B: expected SEQUENCE in signedAttrs, got tag=0x%02X", saTag];
                break;
            }
            RMByteRange attr = { sa.p, sa.p + saLen };
            sa.p += saLen;

            NSData *attrOID = RMReadOID(&attr);
            if (attrOID && RMOIDEquals(attrOID, kOID_messageDigest, sizeof(kOID_messageDigest))) {
                [Logger debug:@"[RMReceipt] validatePKCS7 Step B: found messageDigest OID"];
                if (!RMReadTagAndLength(&attr, &saTag, &saLen)) {
                    [Logger debug:@"[RMReceipt] validatePKCS7 FAIL B: cannot read messageDigest SET"];
                    break;
                }
                if (saTag == RM_ASN1_SET) {
                    attr.end = attr.p + saLen;
                    foundMessageDigest = RMReadOctetString(&attr);
                }
                break;
            }
        }

        // Compute digest of the content.
        unsigned char computedDigest[CC_SHA256_DIGEST_LENGTH];
        if (useSHA256) {
            CC_SHA256(contentData.bytes, (CC_LONG)contentData.length, computedDigest);
        } else {
            CC_SHA1(contentData.bytes, (CC_LONG)contentData.length, computedDigest);
        }
        NSData *computedDigestData = [NSData dataWithBytes:computedDigest length:digestLength];

        if (!foundMessageDigest) {
            [Logger debug:@"[RMReceipt] validatePKCS7 FAIL B: messageDigest not found in signedAttrs"];
            CFRelease(trust);
            CFRelease(signerCert);
            CFRelease(policy);
            return nil;
        }

        if (![foundMessageDigest isEqualToData:computedDigestData]) {
            [Logger debug:@"[RMReceipt] validatePKCS7 FAIL B: message digest mismatch"];
            CFRelease(trust);
            CFRelease(signerCert);
            CFRelease(policy);
            return nil;
        }
        [Logger debug:@"[RMReceipt] validatePKCS7 Step B OK: message digest verified"];

        // CMS signs the SET encoding, while the parser stores only its contents.
        NSMutableData *reencoded = [NSMutableData data];
        uint8_t setTag = 0x31; // SET, CONSTRUCTED
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
        signaturePayload = reencoded;
    } else {
        // Apple receipts may omit signed attributes and sign the content directly.
        [Logger debug:@"[RMReceipt] validatePKCS7: no signed attributes; verifying content directly"];
        signaturePayload = contentData;
    }

    // --- Step D: Verify RSA signature ---
    SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
    if (!publicKey) {
        [Logger debug:@"[RMReceipt] validatePKCS7 FAIL D: could not copy public key from trust"];
        CFRelease(trust);
        CFRelease(signerCert);
        CFRelease(policy);
        return nil;
    }

    CFErrorRef verifyError = NULL;
    unsigned char signatureDigest[CC_SHA256_DIGEST_LENGTH];
    if (useSHA256) {
        CC_SHA256(signaturePayload.bytes, (CC_LONG)signaturePayload.length, signatureDigest);
    } else {
        CC_SHA1(signaturePayload.bytes, (CC_LONG)signaturePayload.length, signatureDigest);
    }
    NSData *signatureDigestData = [NSData dataWithBytes:signatureDigest length:digestLength];
    BOOL signatureValid = SecKeyVerifySignature(publicKey,
                                                 algorithm,
                                                 (__bridge CFDataRef)signatureDigestData,
                                                 (__bridge CFDataRef)signatureData,
                                                 &verifyError);

    if (!signatureValid) {
        [Logger debug:@"[RMReceipt] validatePKCS7 FAIL D: signature verification failed: %@", verifyError];
        if (verifyError) CFRelease(verifyError);
    } else {
        [Logger debug:@"[RMReceipt] validatePKCS7 Step D OK: signature verified"];
    }

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
