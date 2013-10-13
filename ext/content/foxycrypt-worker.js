/**
 * For license terms, see license.txt.
 *
 * This file:
 *   - handles requests from foxycrypt.js, via foxycrypt.jsm.
 *   - performs key (un)wrap.
 *   - uses js-ctypes to pass calls to NSS.
 *
 * For more details, see README.md.
 */

// turn logging output on,off
var DEBUG = true;

function log(aMessage) {
    if (!DEBUG) { return; }
    dump("# worker:  " + aMessage + "\n");
}

// These enumerations are filled in when "init" is sent from the jsm
var KEY_FORMAT;
var KEY_TYPE;
var OP_TYPE = { INITIALIZE:  'initialize', };


// ===== KEY WRAP, UNWRAP ======================================================
unwrap = function worker__unwrap(kek, wrappedKey, format) {
    if (wrappedKey.privateKey) {
        return {
            publicKey:  wrappedKey.publicKey,
            privateKey:  _unwrap(wrappedKey.privateKey, format),
        }
    } else {
        return _unwrap(kek, wrappedKey, format);
    }
};

_unwrap = function worker_unwrap(kek, wrappedKey, format) {
    // ignoring format arg
    log('--> _unwrap()');
    
    if (!wrappedKey.iv || !wrappedKey.encrypted) {
        log('    _unwrap:  Error, wrapped key missing iv and/or encrypted data');
        throw new Error('_unwrap:  wrapped key missing iv and/or encrypted data');
    }
    
    var alg = {
        name:  'AES-CBC',
        iv:  wrappedKey.iv,
    };
    
    var args = {
        alg:  alg,
        key:  kek,
        buf:  wrappedKey.encrypted,
    };
    
    var key = WeaveCrypto.decrypt_sym(args);
    var keyStr = abx2str(key);
    log('    unwrap, keyStr:  ' + keyStr);
    
    key = JSON.parse(keyStr);
    key.keyData = hex2u8a(key.keyData);
    log('    _unwrap, key.keyData:  ' + JSON.stringify(keyStr));
    log('<-- _unwrap()');
    return key;
};

wrap = function worker__wrap(kek, key) {
    if (key.privateKey) {
        return {
            publicKey:  key.publicKey,
            privateKey:  _wrap(key.privateKey),
        }
    } else {
        return _wrap(kek, key);
    }
};

_wrap = function worker_wrap(kek, key) {
    log('--> _wrap()');
    var wrappedKey = {
        type:  key.type,
        format:  key.format,
        algorithm:  key.algorithm,
        extractable:  key.extractable,
        keyUsage:  key.keyUsage,
    };
    
    var alg = {
        name:  'AES-CBC',
        iv:  WeaveCrypto.generateRandomBytes(16),
    };
    
    var kd = key.keyData;
    
    key.keyData = abx2hex(key.keyData);
    var args = {
        alg:  alg,
        key:  kek,
        buf:  str2u8a(JSON.stringify(key)),
    };
    
    wrappedKey.encrypted = WeaveCrypto.encrypt_sym(args);
    wrappedKey.iv = alg.iv;
    log('<-- _wrap()');
    return wrappedKey;
};

// ===== HANDLE POST_MESSAGE FROM THE JSM ======================================
// This is the entry point for this file.  It handles calls from the jsm,
//     and returns results to it.
onmessage = function workerOnMessage (evt) {
    log("--> onmessage()");  //, evt.data:  " + JSON.stringify(evt.data));
    let result;

    try {
        switch (evt.data.args.opType) {
            case OP_TYPE.INITIALIZE:
                log("--> onmessage.initialize");
                if (evt.data.args.opTypeEnum) {
                    log('    onmessage.initialize, setting enums');
                    KEY_FORMAT = evt.data.args.keyFormatEnum;
                    KEY_TYPE = evt.data.args.keyTypeEnum;
                    OP_TYPE = evt.data.args.opTypeEnum;
                }
                if (evt.data.args.nssPath) {
                    log('    onmessage.initialize, initNSS()');
                    WeaveCrypto.initNSS(evt.data.args.nssPath);
                }
                log("<-- onmessage.initialize");
                break;
            case OP_TYPE.ENCRYPT:
                log('--> onmessage.encrypt()');
                evt.data.args.key = unwrap(evt.data.kek, evt.data.args.key);
                if (evt.data.args.key.type === KEY_TYPE.SECRET) {
                    result = WeaveCrypto.encrypt_sym(evt.data.args);
                } else {
                    result = WeaveCrypto.encrypt_asym(evt.data.args);
                }
                log('<-- onmessage.encrypt()');
                break;
            case OP_TYPE.DECRYPT:
                log('--> onmessage.decrypt()');
                evt.data.args.key = unwrap(evt.data.kek, evt.data.args.key);
                if (evt.data.args.key.type === KEY_TYPE.SECRET) {
                    result = WeaveCrypto.decrypt_sym(evt.data.args);
                } else {
                    result = WeaveCrypto.decrypt_asym(evt.data.args);
                }
                log('<-- onmessage.decrypt()');
                break;
            case OP_TYPE.SIGN:
                evt.data.args.key = unwrap(evt.data.kek, evt.data.args.key);
                result = WeaveCrypto.sign(evt.data.args);
                break;
            case OP_TYPE.VERIFY:
                evt.data.args.key = unwrap(evt.data.kek, evt.data.args.key);
                result = WeaveCrypto.verify(evt.data.args);
                break;
            case OP_TYPE.GENERATE_KEY:
                log('--> onmessage.generateKey()');
                if (!evt.data.kek) {
                    // There is no kek, so generate it, and return it unwrapped.
                    log('    onmessage.generate_key, no kek arg, generating kek');
                    result = WeaveCrypto.generateKey_sym(evt.data.args);
                } else {
                    if (evt.data.args.keyType === KEY_TYPE.SECRET) {
                        result = WeaveCrypto.generateKey_sym(evt.data.args);
                    } else {
                        result = WeaveCrypto.generateKey_asym(evt.data.args);
                    }
                    
                    result = wrap(evt.data.kek, result);
                }
                log('<-- onmessage.generateKey()');
                break;
            case OP_TYPE.DERIVE_KEY:
                // Since it's using passphrase, don't need to decrypt.
                // If you change to real derive key (from key material),
                //   you'll need to unwrap the key material.
                result = WeaveCrypto.deriveKeyFromPassphrase(evt.data.args);
                log('    onmessage.derive, result:  ' + JSON.stringify(result));
                result = wrap(evt.data.kek, result);
                break;
            case OP_TYPE.IMPORT_KEY:
                log('--> onmessage.import()');
                result = WeaveCrypto.importKey(evt.data.args);
                result = wrap(evt.data.kek, result);
                log('<-- onmessage.import()');
                break;
            case OP_TYPE.EXPORT_KEY:
                if (evt.data.args.key.extractable === true) {
                    result = unwrap(evt.data.kek, evt.data.args.key, evt.data.args.format);
                } else {
                    log('    onmessage.export, Error: attempting to export non-exportable key');
                    throw new Error('attempting to export non-exportable key');
                }
                break;
            case OP_TYPE.GET_RANDOM_VALUES:
                result = WeaveCrypto.getRandomValues(evt.data.args.array);
                break;
            default:
                log('*   onmessage().default, operation type not recognized:  ' + evt.data.args.opType);
                log('evt.data:  ' + JSON.stringify(evt.data));
                throw new Error('operation type not recognized');
                break;
        }
    } catch (ex) {
        log(ex);
        log(ex.stack);
        result = { errorOccurred: ex.message };
    }
    
    log('<-- onmessage, callbackId=' + evt.data.callbackId);// + ',  ' + JSON.stringify(result));
    postMessage({ result: result, callbackId: evt.data.callbackId, });
};


// ===== JS_CTYPES SETUP AND CALLS TO NSS ======================================
var WeaveCrypto = {
    debug: true,
    nss: null,
    nss_t: null,
    
    log: function WC_log (message) {
        if (!this.debug) return;
        dump("# Weave: " + message + "\n");
    },

    shutdown: function WC_shutdown () {
        this.log("closing nsslib");
        this.nsslib.close();
    },

    fullPathToLib: null,

    initNSS: function WC_initNSS (aNSSPath) {
        this.log("--> initNSS()");
        // Open the NSS library.
        this.fullPathToLib = aNSSPath;
        // XXX really want to be able to pass specific dlopen flags here.
        var nsslib;
        
        this.log("    initNSS, ctypes.open()");
        nsslib = ctypes.open(this.fullPathToLib);

        this.nsslib = nsslib;
        this.log("    initNSS, Initializing NSS types and function declarations...");

        this.nss = {};
        this.nss_t = {};

        // nsprpub/pr/include/prtypes.h#435
        // typedef PRIntn PRBool; --> int
        this.nss_t.PRBool = ctypes.int;
        // security/nss/lib/util/seccomon.h#91
        // typedef enum
        this.nss_t.SECStatus = ctypes.int;
        // security/nss/lib/softoken/secmodt.h#59
        // typedef struct PK11SlotInfoStr PK11SlotInfo; (defined in secmodti.h)
        this.nss_t.PK11SlotInfo = ctypes.void_t;
        // security/nss/lib/util/pkcs11t.h
        this.nss_t.CK_MECHANISM_TYPE = ctypes.unsigned_long;
        this.nss_t.CK_ATTRIBUTE_TYPE = ctypes.unsigned_long;
        this.nss_t.CK_KEY_TYPE = ctypes.unsigned_long;
        this.nss_t.CK_OBJECT_HANDLE = ctypes.unsigned_long;
        // security/nss/lib/softoken/secmodt.h#359
        // typedef enum PK11Origin
        this.nss_t.PK11Origin = ctypes.int;
        // PK11Origin enum values...
        this.nss.PK11_OriginUnwrap = 4;
        // security/nss/lib/softoken/secmodt.h#61
        // typedef struct PK11SymKeyStr PK11SymKey; (defined in secmodti.h)
        this.nss_t.PK11SymKey = ctypes.void_t;
        // security/nss/lib/util/secoidt.h#454
        // typedef enum
        this.nss_t.SECOidTag = ctypes.int;
        // security/nss/lib/util/seccomon.h#64
        // typedef enum
        this.nss_t.SECItemType = ctypes.int;
        // SECItemType enum values...
        this.nss.SIBUFFER = 0;
        // security/nss/lib/softoken/secmodt.h#62 (defined in secmodti.h)
        // typedef struct PK11ContextStr PK11Context;
        this.nss_t.PK11Context = ctypes.void_t;
        // Needed for SECKEYPrivateKey struct def'n, but I don't think we need to actually access it.
        this.nss_t.PLArenaPool = ctypes.void_t;
        // security/nss/lib/cryptohi/keythi.h#45
        // typedef enum
        this.nss_t.KeyType = ctypes.int;
        // security/nss/lib/softoken/secmodt.h#201
        // typedef PRUint32 PK11AttrFlags;
        this.nss_t.PK11AttrFlags = ctypes.unsigned_int;
        // security/nss/lib/util/secoidt.h#454
        // typedef enum
        this.nss_t.SECOidTag = ctypes.int;
        // security/nss/lib/util/seccomon.h#83
        // typedef struct SECItemStr SECItem; --> SECItemStr defined right below it
        this.nss_t.SECItem = ctypes.StructType(
            "SECItem",
            [{ type: this.nss_t.SECItemType },
             { data: ctypes.unsigned_char.ptr },
             { len: ctypes.int } ] );
        // security/nss/lib/softoken/secmodt.h#65
        // typedef struct PK11RSAGenParamsStr --> def'n on line 139
        this.nss_t.PK11RSAGenParams = ctypes.StructType(
            "PK11RSAGenParams",
            [{ keySizeInBits: ctypes.int },
             { pe: ctypes.unsigned_long } ] );
        // security/nss/lib/cryptohi/keythi.h#233
        // typedef struct SECKEYPrivateKeyStr SECKEYPrivateKey; --> def'n right above it
        this.nss_t.SECKEYPrivateKey = ctypes.StructType(
            "SECKEYPrivateKey", [{ arena: this.nss_t.PLArenaPool.ptr },
                           { keyType: this.nss_t.KeyType },
                           { pkcs11Slot: this.nss_t.PK11SlotInfo.ptr },
                           { pkcs11ID: this.nss_t.CK_OBJECT_HANDLE },
                           { pkcs11IsTemp: this.nss_t.PRBool },
                           { wincx: ctypes.voidptr_t },
                           { staticflags: ctypes.unsigned_int }]);
        // security/nss/lib/cryptohi/keythi.h#78
        // typedef struct SECKEYRSAPublicKeyStr --> def'n right above it
        this.nss_t.SECKEYRSAPublicKey = ctypes.StructType(
            "SECKEYRSAPublicKey", [{ arena: this.nss_t.PLArenaPool.ptr },
                             { modulus: this.nss_t.SECItem },
                             { publicExponent: this.nss_t.SECItem }]);
        // security/nss/lib/cryptohi/keythi.h#189
        // typedef struct SECKEYPublicKeyStr SECKEYPublicKey; --> def'n right above it
        this.nss_t.SECKEYPublicKey = ctypes.StructType(
            "SECKEYPublicKey", [{ arena: this.nss_t.PLArenaPool.ptr },
                          { keyType: this.nss_t.KeyType },
                          { pkcs11Slot: this.nss_t.PK11SlotInfo.ptr },
                          { pkcs11ID: this.nss_t.CK_OBJECT_HANDLE },
                          { rsa: this.nss_t.SECKEYRSAPublicKey }]);
        // XXX: "rsa" et al into a union here!
        // { dsa: SECKEYDSAPublicKey },
        // { dh:  SECKEYDHPublicKey },
        // { kea: SECKEYKEAPublicKey },
        // { fortezza: SECKEYFortezzaPublicKey },
        // { ec:  SECKEYECPublicKey } ]);
        // security/nss/lib/util/secoidt.h#52
        // typedef struct SECAlgorithmIDStr --> def'n right below it
        this.nss_t.SECAlgorithmID = ctypes.StructType(
            "SECAlgorithmID", [{ algorithm: this.nss_t.SECItem },
                         { parameters: this.nss_t.SECItem }]);
        // security/nss/lib/certdb/certt.h#98
        // typedef struct CERTSubjectPublicKeyInfoStrA --> def'n on line 160
        this.nss_t.CERTSubjectPublicKeyInfo = ctypes.StructType(
            "CERTSubjectPublicKeyInfo", [{ arena: this.nss_t.PLArenaPool.ptr },
                                   { algorithm: this.nss_t.SECAlgorithmID },
                                   { subjectPublicKey: this.nss_t.SECItem }]);
        
        // source/nsprpub/pr/include/prtypes.h
        this.nss.PR_TRUE = 1;
        this.nss.PR_FALSE = 0;

        // security/nss/lib/util/pkcs11t.h
        this.nss.CKK_RSA = 0x0;
        this.nss.CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0000;
        this.nss.CKM_AES_KEY_GEN = 0x1080;
        this.nss.CKM_AES_CBC = 0x1082;
        this.nss.CKM_AES_CTR = 0x1086;
        this.nss.CKM_AES_GCM = 0x1087;
        this.nss.CKM_AES_CCM = 0x1088;
        this.nss.CKM_AES_CTS = 0x1089;
        
        this.nss.CKA_ENCRYPT = 0x104;
        this.nss.CKA_DECRYPT = 0x105;
        this.nss.CKA_WRAP = 0x106;
        this.nss.CKA_UNWRAP = 0x107;

        // security/nss/lib/util/secoidt.h
        this.nss.DES_EDE3_CBC = 156;
        this.nss.AES_128_CBC = 184;
        this.nss.AES_192_CBC = 186;
        this.nss.AES_256_CBC = 188;
        
        // security/nss/lib/softoken/secmodt.h
        this.nss.PK11_ATTR_SESSION = 0x02;
        this.nss.PK11_ATTR_PUBLIC = 0x08;
        this.nss.PK11_ATTR_SENSITIVE = 0x40;

        // security/nss/lib/util/secoidt.h
        this.nss.SEC_OID_UNKNOWN = 0;
        this.nss.SEC_OID_PKCS1_RSA_ENCRYPTION = 16;
        this.nss.SEC_OID_PKCS5_PBKDF2 = 291;
        this.nss.SEC_OID_HMAC_SHA1 = 294;

        // security/nss/lib/pk11wrap/pk11pub.h#286
        // SECStatus PK11_GenerateRandom(unsigned char *data,int len);
        this.nss.PK11_GenerateRandom = nsslib.declare("PK11_GenerateRandom",
            ctypes.default_abi, this.nss_t.SECStatus,
            ctypes.unsigned_char.ptr, ctypes.int);
        // security/nss/lib/pk11wrap/pk11pub.h#74
        // PK11SlotInfo *PK11_GetInternalSlot(void);
        this.nss.PK11_GetInternalSlot = nsslib.declare("PK11_GetInternalSlot",
            ctypes.default_abi, this.nss_t.PK11SlotInfo.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#73
        // PK11SlotInfo *PK11_GetInternalKeySlot(void);
        this.nss.PK11_GetInternalKeySlot = nsslib.declare("PK11_GetInternalKeySlot",
            ctypes.default_abi, this.nss_t.PK11SlotInfo.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#328
        // PK11SymKey *PK11_KeyGen(PK11SlotInfo *slot,CK_MECHANISM_TYPE type, SECItem *param, int keySize,void *wincx);
        this.nss.PK11_KeyGen = nsslib.declare("PK11_KeyGen",
            ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
            this.nss_t.PK11SlotInfo.ptr, this.nss_t.CK_MECHANISM_TYPE,
            this.nss_t.SECItem.ptr, ctypes.int, ctypes.voidptr_t);

        // SIGNING API //////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////

        // security/nss/pk11wrap/pk11pub.h#682
        // int PK11_SignatureLength(SECKEYPrivateKey *key);
        this.nss.PK11_SignatureLen = nsslib.declare("PK11_SignatureLen",
            ctypes.default_abi,
            ctypes.int,
            this.nss_t.SECKEYPrivateKey.ptr);

        // security/nss/pk11wrap/pk11pub.h#684
        // SECStatus PK11_Sign(SECKEYPrivateKey *key, SECItem *sig, SECItem *hash);
        this.nss.PK11_Sign = nsslib.declare("PK11_Sign",
            ctypes.default_abi,
            this.nss_t.SECStatus,
            this.nss_t.SECKEYPrivateKey.ptr,
            this.nss_t.SECItem.ptr,
            this.nss_t.SECItem.ptr);

        // security/nss/pk11wrap/pk11pub.h#687
        // SECStatus PK11_Verify(SECKEYPublicKey *key, SECItem *sig, SECItem *hash, void *wincx);
        this.nss.PK11_Verify = nsslib.declare("PK11_Verify",
            ctypes.default_abi,
            this.nss_t.SECStatus,
            this.nss_t.SECKEYPublicKey.ptr,
            this.nss_t.SECItem.ptr,
            this.nss_t.SECItem.ptr,
            ctypes.voidptr_t);
        // END SIGNING API
        //////////////////////////////////////////////////////////////////////////

        // security/nss/lib/pk11wrap/pk11pub.h#477
        // SECStatus PK11_ExtractKeyValue(PK11SymKey *symKey);
        this.nss.PK11_ExtractKeyValue = nsslib.declare("PK11_ExtractKeyValue",
            ctypes.default_abi, this.nss_t.SECStatus,
            this.nss_t.PK11SymKey.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#478
        // SECItem * PK11_GetKeyData(PK11SymKey *symKey);
        this.nss.PK11_GetKeyData = nsslib.declare("PK11_GetKeyData",
            ctypes.default_abi, this.nss_t.SECItem.ptr,
            this.nss_t.PK11SymKey.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#278
        // CK_MECHANISM_TYPE PK11_AlgtagToMechanism(SECOidTag algTag);
        this.nss.PK11_AlgtagToMechanism = nsslib.declare("PK11_AlgtagToMechanism",
            ctypes.default_abi, this.nss_t.CK_MECHANISM_TYPE,
            this.nss_t.SECOidTag);
        // security/nss/lib/pk11wrap/pk11pub.h#270
        // int PK11_GetIVLength(CK_MECHANISM_TYPE type);
        this.nss.PK11_GetIVLength = nsslib.declare("PK11_GetIVLength",
            ctypes.default_abi, ctypes.int,
            this.nss_t.CK_MECHANISM_TYPE);
        // security/nss/lib/pk11wrap/pk11pub.h#269
        // int PK11_GetBlockSize(CK_MECHANISM_TYPE type,SECItem *params);
        this.nss.PK11_GetBlockSize = nsslib.declare("PK11_GetBlockSize",
            ctypes.default_abi, ctypes.int,
            this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECItem.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#293
        // CK_MECHANISM_TYPE PK11_GetPadMechanism(CK_MECHANISM_TYPE);
        this.nss.PK11_GetPadMechanism = nsslib.declare("PK11_GetPadMechanism",
            ctypes.default_abi, this.nss_t.CK_MECHANISM_TYPE,
            this.nss_t.CK_MECHANISM_TYPE);
        // security/nss/lib/pk11wrap/pk11pub.h#271
        // SECItem *PK11_ParamFromIV(CK_MECHANISM_TYPE type,SECItem *iv);
        this.nss.PK11_ParamFromIV = nsslib.declare("PK11_ParamFromIV",
            ctypes.default_abi, this.nss_t.SECItem.ptr,
            this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECItem.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#301
        // PK11SymKey *PK11_ImportSymKey(PK11SlotInfo *slot, CK_MECHANISM_TYPE type, PK11Origin origin,
        //                               CK_ATTRIBUTE_TYPE operation, SECItem *key, void *wincx);
        this.nss.PK11_ImportSymKey = nsslib.declare("PK11_ImportSymKey",
            ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
            this.nss_t.PK11SlotInfo.ptr, this.nss_t.CK_MECHANISM_TYPE, this.nss_t.PK11Origin,
            this.nss_t.CK_ATTRIBUTE_TYPE, this.nss_t.SECItem.ptr, ctypes.voidptr_t);
        // security/nss/lib/pk11wrap/pk11pub.h#672
        // PK11Context *PK11_CreateContextBySymKey(CK_MECHANISM_TYPE type, CK_ATTRIBUTE_TYPE operation,
        //                                         PK11SymKey *symKey, SECItem *param);
        this.nss.PK11_CreateContextBySymKey = nsslib.declare("PK11_CreateContextBySymKey",
            ctypes.default_abi, this.nss_t.PK11Context.ptr,
            this.nss_t.CK_MECHANISM_TYPE, this.nss_t.CK_ATTRIBUTE_TYPE,
            this.nss_t.PK11SymKey.ptr, this.nss_t.SECItem.ptr);
        
        // security/nss/lib/pk11wrap/pk11pub.h#685
        // SECStatus PK11_CipherOp(
        //     PK11Context *context,
        //     unsigned char *out
        //     int *outlen,
        //     int maxout,
        //     unsigned char *in,
        //     int inlen);
        this.nss.PK11_CipherOp = nsslib.declare("PK11_CipherOp",
            ctypes.default_abi,
            this.nss_t.SECStatus,
            this.nss_t.PK11Context.ptr,
            ctypes.unsigned_char.ptr,
            ctypes.int.ptr,
            ctypes.int,
            ctypes.unsigned_char.ptr,
            ctypes.int);
        
        // security/nss/lib/pk11wrap/pk11pub.h#688
        // SECStatus PK11_DigestFinal(PK11Context *context, unsigned char *data,
        //                            unsigned int *outLen, unsigned int length);
        this.nss.PK11_DigestFinal = nsslib.declare("PK11_DigestFinal",
            ctypes.default_abi, this.nss_t.SECStatus,
            this.nss_t.PK11Context.ptr, ctypes.unsigned_char.ptr,
            ctypes.unsigned_int.ptr, ctypes.unsigned_int);
        // security/nss/lib/pk11wrap/pk11pub.h#507
        // SECKEYPrivateKey *PK11_GenerateKeyPairWithFlags(PK11SlotInfo *slot,
        //                                                 CK_MECHANISM_TYPE type, void *param, SECKEYPublicKey **pubk,
        //                                                 PK11AttrFlags attrFlags, void *wincx);
        this.nss.PK11_GenerateKeyPairWithFlags = nsslib.declare("PK11_GenerateKeyPairWithFlags",
            ctypes.default_abi, this.nss_t.SECKEYPrivateKey.ptr,
            this.nss_t.PK11SlotInfo.ptr, this.nss_t.CK_MECHANISM_TYPE, ctypes.voidptr_t,
            this.nss_t.SECKEYPublicKey.ptr.ptr, this.nss_t.PK11AttrFlags, ctypes.voidptr_t);
        // security/nss/lib/pk11wrap/pk11pub.h#466
        // SECStatus PK11_SetPrivateKeyNickname(SECKEYPrivateKey *privKey, const char *nickname);
        this.nss.PK11_SetPrivateKeyNickname = nsslib.declare("PK11_SetPrivateKeyNickname",
            ctypes.default_abi, this.nss_t.SECStatus,
            this.nss_t.SECKEYPrivateKey.ptr, ctypes.char.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#731
        // SECAlgorithmID * PK11_CreatePBEV2AlgorithmID(SECOidTag pbeAlgTag, SECOidTag cipherAlgTag,
        //                                              SECOidTag prfAlgTag, int keyLength, int iteration,
        //                                              SECItem *salt);
        this.nss.PK11_CreatePBEV2AlgorithmID = nsslib.declare("PK11_CreatePBEV2AlgorithmID",
            ctypes.default_abi, this.nss_t.SECAlgorithmID.ptr,
            this.nss_t.SECOidTag, this.nss_t.SECOidTag, this.nss_t.SECOidTag,
            ctypes.int, ctypes.int, this.nss_t.SECItem.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#736
        // PK11SymKey * PK11_PBEKeyGen(PK11SlotInfo *slot, SECAlgorithmID *algid,  SECItem *pwitem, PRBool faulty3DES, void *wincx);
        this.nss.PK11_PBEKeyGen = nsslib.declare("PK11_PBEKeyGen",
            ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
            this.nss_t.PK11SlotInfo.ptr, this.nss_t.SECAlgorithmID.ptr,
            this.nss_t.SECItem.ptr, this.nss_t.PRBool, ctypes.voidptr_t);
        // security/nss/lib/pk11wrap/pk11pub.h#574
        // SECStatus PK11_WrapPrivKey(PK11SlotInfo *slot, PK11SymKey *wrappingKey,
        //                            SECKEYPrivateKey *privKey, CK_MECHANISM_TYPE wrapType,
        //                            SECItem *param, SECItem *wrappedKey, void *wincx);
        this.nss.PK11_WrapPrivKey = nsslib.declare("PK11_WrapPrivKey",
            ctypes.default_abi, this.nss_t.SECStatus,
            this.nss_t.PK11SlotInfo.ptr, this.nss_t.PK11SymKey.ptr,
            this.nss_t.SECKEYPrivateKey.ptr, this.nss_t.CK_MECHANISM_TYPE,
            this.nss_t.SECItem.ptr, this.nss_t.SECItem.ptr, ctypes.voidptr_t);
        
        // security/nss/lib/pk11wrap/pk11pub.h [364]
        // SECStatus PK11_WrapSymKey( CK_MECHANISM_TYPE type,
        //                            SECItem *param,
        //                            PK11SymKey *wrappingKey,
        //                            PK11SymKey *symKey,
        //                            SECItem *wrappedKey)
        this.nss.PK11_WrapSymKey = nsslib.declare('PK11_WrapSymKey',
                ctypes.default_abi, this.nss_t.SECStatus,
                this.nss_t.CK_MECHANISM_TYPE,
                this.nss_t.SECItem.ptr,
                this.nss_t.PK11SymKey.ptr,
                this.nss_t.PK11SymKey.ptr,
                this.nss_t.SECItem.ptr);
        // security/nss/lib/cryptohi/keyhi.h#159
        // SECItem* SECKEY_EncodeDERSubjectPublicKeyInfo(SECKEYPublicKey *pubk);
        this.nss.SECKEY_EncodeDERSubjectPublicKeyInfo = nsslib.declare("SECKEY_EncodeDERSubjectPublicKeyInfo",
            ctypes.default_abi, this.nss_t.SECItem.ptr,
            this.nss_t.SECKEYPublicKey.ptr);
        // security/nss/lib/cryptohi/keyhi.h#165
        // CERTSubjectPublicKeyInfo * SECKEY_DecodeDERSubjectPublicKeyInfo(SECItem *spkider);
        this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo = nsslib.declare("SECKEY_DecodeDERSubjectPublicKeyInfo",
            ctypes.default_abi, this.nss_t.CERTSubjectPublicKeyInfo.ptr,
            this.nss_t.SECItem.ptr);
        // security/nss/lib/cryptohi/keyhi.h#179
        // SECKEYPublicKey * SECKEY_ExtractPublicKey(CERTSubjectPublicKeyInfo *);
        this.nss.SECKEY_ExtractPublicKey = nsslib.declare("SECKEY_ExtractPublicKey",
            ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr,
            this.nss_t.CERTSubjectPublicKeyInfo.ptr);
        
        // security/nss/lib/pk11wrap/pk11pub.h
        // SECStatus PK11_PubDecryptRaw(SECKEYPrivateKey *key, unsigned char *data,
        //         unsigned *outLen, unsigned int maxLen, unsigned char *enc, unsigned encLen);
        
        // security/nss/lib/pk11wrap/pk11pub.h
        // The encrypt function that complements the above decrypt function.
        this.nss.PK11_PubEncryptRaw = nsslib.declare('PK11_PubEncryptRaw',
                ctypes.default_abi, this.nss_t.SECStatus,
                this.nss_t.SECKEYPublicKey.ptr,  // SECKEYPublicKey *key
                ctypes.unsigned_char.ptr,  // unsigned char *enc
                ctypes.unsigned_char.ptr,  // unsigned char *data
                ctypes.unsigned_int,  // unsigned dataLen
                ctypes.voidptr_t);  // void *wincx
        
        // security/nss/lib/pk11wrap/pk11pub.h
        this.nss.PK11_PrivDecryptPKCS1 = nsslib.declare('PK11_PrivDecryptPKCS1',
                ctypes.default_abi, this.nss_t.SECStatus,
                this.nss_t.SECKEYPrivateKey.ptr,  // SECKEYPrivateKey *key
                ctypes.unsigned_char.ptr,  // unsigned char *data
                ctypes.unsigned_int.ptr,  // unsigned *outLen
                ctypes.unsigned_int,  // unsigned int maxLen
                ctypes.unsigned_char.ptr,  // unsigned char *enc
                ctypes.unsigned_int);  // unsigned encLen
        
        // security/nss/lib/pk11wrap/pk11pub.h
        this.nss.PK11_PubEncryptPKCS1 = nsslib.declare('PK11_PubEncryptPKCS1',
                ctypes.default_abi, this.nss_t.SECStatus,
                this.nss_t.SECKEYPublicKey.ptr,  // SECKEYPublicKey *key
                ctypes.unsigned_char.ptr,  // unsigned char *enc
                ctypes.unsigned_char.ptr,  // unsigned char *data
                ctypes.unsigned_int,  // unsigned dataLen
                ctypes.voidptr_t);  // void *wincx
        
        // security/nss/lib/nss/utilwrap.c
        this.nss.ATOB_ConvertAsciiToItem = nsslib.declare('ATOB_ConvertAsciiToItem',
                ctypes.default_abi, this.nss_t.SECStatus,
                this.nss_t.SECItem.ptr,  // SECItem *binary_item
                ctypes.char.ptr);  // const char *ascii
    
        // returns key strength in bytes (not bits)
        // unsigned SECKEY_PublicKeyStrength(const SECKEYPublicKey *pubk)
        this.nss.SECKEY_PublicKeyStrength = nsslib.declare('SECKEY_PublicKeyStrength',
                ctypes.default_abi, ctypes.unsigned_int,
                this.nss_t.SECKEYPublicKey.ptr);
        
        // security/nss/lib/cryptohi/keyhi.h
        // SECKEYPublicKey *SECKEY_ConvertToPublicKey(SECKEYPrivateKey *privateKey);
        this.nss.SECKEY_ConvertToPublicKey = nsslib.declare('SECKEY_ConvertToPublicKey',
                ctypes.default_abi, this.nss_t.SECKEYPublicKey.ptr,
                this.nss_t.SECKEYPrivateKey.ptr);
        
        // source/security/nss/lib/pk11wrap/pk11pub.h
        this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey = nsslib.declare('PK11_ImportDERPrivateKeyInfoAndReturnKey',
                ctypes.default_abi, this.nss_t.SECStatus,
                this.nss_t.PK11SlotInfo.ptr,  // PK11SlotInfo *slot
                this.nss_t.SECItem.ptr,  // SECItem *derPKI
                this.nss_t.SECItem.ptr,  // SECItem *nickname
                this.nss_t.SECItem.ptr,  // SECItem *publicValue
                ctypes.int,  // PRBool isPerm
                ctypes.int,  // PRBool isPrivate
                ctypes.unsigned_int,  // unsigned int usage
                this.nss_t.SECKEYPrivateKey.ptr.ptr,  // SECKEYPrivateKey** privk
                ctypes.voidptr_t);  // void *wincx
        
        // security/nss/lib/pk11wrap/pk11pub.h#377
        // SECStatus PK11_PubWrapSymKey(CK_MECHANISM_TYPE type, SECKEYPublicKey *pubKey,
        //                              PK11SymKey *symKey, SECItem *wrappedKey);
        this.nss.PK11_PubWrapSymKey = nsslib.declare("PK11_PubWrapSymKey",
            ctypes.default_abi, this.nss_t.SECStatus,
            this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECKEYPublicKey.ptr,
            this.nss_t.PK11SymKey.ptr, this.nss_t.SECItem.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#568
        // SECKEYPrivateKey *PK11_UnwrapPrivKey(PK11SlotInfo *slot,
        //                 PK11SymKey *wrappingKey, CK_MECHANISM_TYPE wrapType,
        //                 SECItem *param, SECItem *wrappedKey, SECItem *label,
        //                 SECItem *publicValue, PRBool token, PRBool sensitive,
        //                 CK_KEY_TYPE keyType, CK_ATTRIBUTE_TYPE *usage, int usageCount,
        //                 void *wincx);
        this.nss.PK11_UnwrapPrivKey = nsslib.declare("PK11_UnwrapPrivKey",
            ctypes.default_abi, this.nss_t.SECKEYPrivateKey.ptr,
            this.nss_t.PK11SlotInfo.ptr, this.nss_t.PK11SymKey.ptr,
            this.nss_t.CK_MECHANISM_TYPE, this.nss_t.SECItem.ptr,
            this.nss_t.SECItem.ptr, this.nss_t.SECItem.ptr,
            this.nss_t.SECItem.ptr, this.nss_t.PRBool,
            this.nss_t.PRBool, this.nss_t.CK_KEY_TYPE,
            this.nss_t.CK_ATTRIBUTE_TYPE.ptr, ctypes.int,
            ctypes.voidptr_t);
        // security/nss/lib/pk11wrap/pk11pub.h#447
        // PK11SymKey *PK11_PubUnwrapSymKey(SECKEYPrivateKey *key, SECItem *wrapppedKey,
        //         CK_MECHANISM_TYPE target, CK_ATTRIBUTE_TYPE operation, int keySize);
        this.nss.PK11_PubUnwrapSymKey = nsslib.declare("PK11_PubUnwrapSymKey",
            ctypes.default_abi, this.nss_t.PK11SymKey.ptr,
            this.nss_t.SECKEYPrivateKey.ptr, this.nss_t.SECItem.ptr,
            this.nss_t.CK_MECHANISM_TYPE, this.nss_t.CK_ATTRIBUTE_TYPE, ctypes.int);
        // security/nss/lib/pk11wrap/pk11pub.h#675
        // void PK11_DestroyContext(PK11Context *context, PRBool freeit);
        this.nss.PK11_DestroyContext = nsslib.declare("PK11_DestroyContext",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.PK11Context.ptr, this.nss_t.PRBool);
        // security/nss/lib/pk11wrap/pk11pub.h#299
        // void PK11_FreeSymKey(PK11SymKey *key);
        this.nss.PK11_FreeSymKey = nsslib.declare("PK11_FreeSymKey",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.PK11SymKey.ptr);
        // security/nss/lib/pk11wrap/pk11pub.h#70
        // void PK11_FreeSlot(PK11SlotInfo *slot);
        this.nss.PK11_FreeSlot = nsslib.declare("PK11_FreeSlot",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.PK11SlotInfo.ptr);
        // security/nss/lib/util/secitem.h#114
        // extern void SECITEM_FreeItem(SECItem *zap, PRBool freeit);
        this.nss.SECITEM_FreeItem = nsslib.declare("SECITEM_FreeItem",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.SECItem.ptr, this.nss_t.PRBool);
        // security/nss/lib/cryptohi/keyhi.h#193
        // extern void SECKEY_DestroyPublicKey(SECKEYPublicKey *key);
        this.nss.SECKEY_DestroyPublicKey = nsslib.declare("SECKEY_DestroyPublicKey",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.SECKEYPublicKey.ptr);
        // security/nss/lib/cryptohi/keyhi.h#186
        // extern void SECKEY_DestroyPrivateKey(SECKEYPrivateKey *key);
        this.nss.SECKEY_DestroyPrivateKey = nsslib.declare("SECKEY_DestroyPrivateKey",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.SECKEYPrivateKey.ptr);
        // security/nss/lib/util/secoid.h#103
        // extern void SECOID_DestroyAlgorithmID(SECAlgorithmID *aid, PRBool freeit);
        this.nss.SECOID_DestroyAlgorithmID = nsslib.declare("SECOID_DestroyAlgorithmID",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.SECAlgorithmID.ptr, this.nss_t.PRBool);
        // security/nss/lib/cryptohi/keyhi.h#58
        // extern void SECKEY_DestroySubjectPublicKeyInfo(CERTSubjectPublicKeyInfo *spki);
        this.nss.SECKEY_DestroySubjectPublicKeyInfo = nsslib.declare("SECKEY_DestroySubjectPublicKeyInfo",
            ctypes.default_abi, ctypes.void_t,
            this.nss_t.CERTSubjectPublicKeyInfo.ptr);
        this.log("<-- initNSS()");
    },
    
    encrypt_sym: function WC_encrypt_sym (args) {
        this.log("--> encrypt_sym()");
        let bufIn = abx2cUchar(args.buf);

        let algConstant = this.getAlgConst(args.alg, args.key);
        log('    encrypt_sym, algConstant:  ' + algConstant);
        let mech = this.nss.PK11_AlgtagToMechanism(algConstant);
        let blockSz = this.nss.PK11_GetBlockSize(mech, null);
        log('    encrypt_sym, blockSz:  ' + blockSz);
        
        // a little bigger than needed is ok
        let bufOutSz = bufIn.length + blockSz;
        
        log('    encrypt_sym, bufOutSz:  ' + bufOutSz);
        let bufOut = new ctypes.ArrayType(ctypes.unsigned_char, bufOutSz)();

        this.log("    encrypt_sym, call _commonCrypt()");
        bufOut = this._commonCrypt(bufIn,
                                   bufOut,
                                   abx2u8a(args.key.keyData),
                                   abx2u8a(args.alg.iv),
                                   this.nss.CKA_ENCRYPT,
                                   algConstant);

        this.log("<-- encrypt_sym()");
        return bufOut;
    },
    
    decrypt_sym: function WC_decrypt_sym (args) {
        this.log("--> decrypt_sym()");
        let bufIn = abx2cUchar(args.buf);

        let algConstant = this.getAlgConst(args.alg, args.key);
        log('    decrypt_sym, algConstant:  ' + algConstant);
        let mech = this.nss.PK11_AlgtagToMechanism(algConstant);
        let blockSz = this.nss.PK11_GetBlockSize(mech, null);
        log('    decrypt_sym, blockSz:  ' + blockSz);
        
        let bufOutSz = bufIn.length;
        let extra = bufIn.length % blockSz;
        if (extra !== 0) {
            bufOutSz += blockSz - extra;
        }
        log('    decrypt_sym, bufOutSz:  ' + bufOutSz);
        let bufOut = new ctypes.ArrayType(ctypes.unsigned_char, bufOutSz)();

        this.log("    decrypt_sym, call _commonCrypt()");
        bufOut = this._commonCrypt(bufIn,
                                   bufOut,
                                   abx2u8a(args.key.keyData),
                                   abx2u8a(args.alg.iv),
                                   this.nss.CKA_DECRYPT,
                                   algConstant);

        this.log("<-- decrypt_sym()");
        return bufOut;
    },

    _commonCrypt: function WC_commonCrypt (input, output, key, iv, operation, algConstant) {
        this.log("--> _commonCrypt()");
        let keyItem = this.abx2SecItem(key);
        let ivItem = this.abx2SecItem(iv);
        // Determine which (padded) PKCS#11 mechanism to use, eg: AES_128_CBC, CKM_AES_CBC, CKM_AES_CBC_PAD
        let mechanism = this.nss.PK11_AlgtagToMechanism(algConstant);
        mechanism = this.nss.PK11_GetPadMechanism(mechanism);
        this.log('    _commonCrypt, pad mechanism:  ' + mechanism);
        if (mechanism == this.nss.CKM_INVALID_MECHANISM) {
            throw new Error("invalid algorithm (can't pad)");
        }

        let ctx, symKey, slot, ivParam;
        try {
            ivParam = this.nss.PK11_ParamFromIV(mechanism, ivItem.address());
            if (ivParam.isNull()) throw new Error("can't convert IV to param");

            slot = this.nss.PK11_GetInternalKeySlot();
            if (slot.isNull()) throw new Error("can't get internal key slot");

            symKey = this.nss.PK11_ImportSymKey(slot, mechanism, this.nss.PK11_OriginUnwrap, operation, keyItem.address(), null);
            if (symKey.isNull()) throw new Error("symkey import failed");

            ctx = this.nss.PK11_CreateContextBySymKey(mechanism, operation, symKey, ivParam);
            if (ctx.isNull()) throw new Error("couldn't create context for symkey");

            let maxOutputSize = output.length;
            let tmpOutputSize = new ctypes.int(); // Note 1: NSS uses a signed int here...

            var ret = this.nss.PK11_CipherOp(ctx, output, tmpOutputSize.address(),
                                       maxOutputSize, input, input.length);
            if (ret) { throw new Error("cipher operation failed, ret:  " + ret); }
            
            let actualOutputSize = tmpOutputSize.value;
            let finalOutput = output.addressOfElement(actualOutputSize);
            maxOutputSize -= actualOutputSize;
            
            // PK11_DigestFinal sure sounds like the last step for *hashing*, but it
            // just seems to be an odd name -- NSS uses this to finish the current
            // cipher operation. You'd think it would be called PK11_CipherOpFinal...
            let tmpOutputSize2 = new ctypes.unsigned_int(); // Note 2: ...but an unsigned here!
            if (this.nss.PK11_DigestFinal(ctx, finalOutput, tmpOutputSize2.address(), maxOutputSize)) {
                throw new Error("cipher finalize failed");
            }

            actualOutputSize += tmpOutputSize2.value;
            let newOutput = ctypes.cast(output, ctypes.unsigned_char.array(actualOutputSize));
            this.log("    _commonCrypt, actualOutputSize:  " + actualOutputSize);
            this.log("<-- _commonCrypt()");
            return cUchar2u8a(newOutput, actualOutputSize);
        } catch (e) {
            this.log("_commonCrypt: failed: " + e);
            throw e;
        } finally {
            if (ctx && !ctx.isNull()) this.nss.PK11_DestroyContext(ctx, true);
            if (symKey && !symKey.isNull()) this.nss.PK11_FreeSymKey(symKey);
            if (slot && !slot.isNull()) this.nss.PK11_FreeSlot(slot);
            if (ivParam && !ivParam.isNull()) this.nss.SECITEM_FreeItem(ivParam, true);
        }
    },
    
    // This generates the key, but it's not clear how to export the private key.
    generateKey_asym: function WC_generateKey_asym (args) {
        this.log("--> generateKey_asym()");
        var pubkey, privkey, spki_der;
        
        // Attributes for the private key. We're just going to wrap and extract the
        // value, so they're not critical. The _PUBLIC attribute just indicates the
        // object can be accessed without being logged into the token.
        var attrFlags = (this.nss.PK11_ATTR_SESSION | this.nss.PK11_ATTR_PUBLIC | this.nss.PK11_ATTR_SENSITIVE);

        try {
            pubKey = new this.nss_t.SECKEYPublicKey.ptr();

            let rsaParams = new this.nss_t.PK11RSAGenParams();
            rsaParams.keySizeInBits = args.alg.modulusLength;
            rsaParams.pe = args.alg.publicExponent;

            slot = this.nss.PK11_GetInternalSlot();
            if (slot.isNull()) throw new Error("couldn't get internal slot");

            // Generate the keypair.
            privKey = this.nss.PK11_GenerateKeyPairWithFlags(slot,
                    this.nss.CKM_RSA_PKCS_KEY_PAIR_GEN,
                    rsaParams.address(),
                    pubKey.address(),
                    attrFlags, null);
            if (privKey.isNull()) throw new Error("keypair generation failed");
            
            // convert public key to der
            pubKey = this.nss.SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey);
            if (pubKey.isNull()) throw new Error("SECKEY_EncodeDERSubjectPublicKeyInfo failed");
            spki_der = cUchar2u8a(pubKey.contents.data, pubKey.contents.len);
            
            // TODO: convert private key to der
            
        } catch (e) {
            this.log('generateKey_asym failed: ' + e);
        } finally {
            if (pubKey && !pubKey.isNull()) this.nss.SECKEY_DestroyPublicKey(pubKey);
            if (privKey && !privKey.isNull()) this.nss.SECKEY_DestroyPrivateKey(privKey);
            if (slot && !slot.isNull()) this.nss.PK11_FreeSlot(slot);
        }
        
        this.log("<-- generateKey_asym()");
        return { publicKey: spki_der, privateKey: privKey, };
    },
    
    encrypt_asym:  function WC_encrypt_asym(args) {
        this.log('--> encrypt_asym()');
        var der_pub, rv, pubKeyInfo, pubKey, bufIn, dataLen,
                modulus_len, bufOut;
        try {
            // get public key
            der_pub = this.abx2SecItem(args.key.keyData);
            this.log('====================================================\\\/');
            this.log('    encrypt_asym, about to SECKEY_DecodeDER...');
            pubKeyInfo = this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo(der_pub.address());
            if (pubKeyInfo.isNull()) { throw new Error("SECKEY_DecodeDERSubjectPublicKeyInfo failed"); }
            this.log('    encrypt_asym, about to SECKEY_Extract...');
            pubKey = this.nss.SECKEY_ExtractPublicKey(pubKeyInfo);
            if (pubKey.isNull()) { throw new Error("SECKEY_ExtractPublicKey failed"); }
            this.log('    encrypt_asym, pubKey:  ' + pubKey);
            
            this.log('    encrypt_asym, about to create bufIN...');
            dataLen = args.buf.byteLength;
            this.log('    encrypt_asym, args.buf.byteLength:  ' + args.buf.byteLength);
            bufIn = abx2cUchar(args.buf);
            this.log('    encrypt_asym, bufIn:  ' + bufIn);
            this.log('    encrypt_asym, bufIn.address():  ' + bufIn.address());
            
            modulus_len = this.nss.SECKEY_PublicKeyStrength(pubKey);
            this.log('    encrypt_asym, modulus_len:  ' + modulus_len);

            bufOut = new Uint8Array(modulus_len);
            for (var i = 0; i < modulus_len; i++) {
                bufOut[i] = 7;  // value doesn't matter, just something to see in logs
            }
            bufOut = abx2cUchar(bufOut);
            this.log('    encrypt_asym, bufOut.address():  ' + bufOut.address());
        
            this.log('    encrypt_asym, about to PK11_PubEncryptPKCS1()...');
            rv = this.nss.PK11_PubEncryptPKCS1(
                    pubKey,   // SECKEYPublicKey *key
                    bufOut,   // unsigned char *enc
                    bufIn,    // unsigned char *data
                    dataLen,  // unsigned dataLen
                    null);    // void *wincx
            if (rv) { throw new Error('PK11_PubEncryptPKCS1 failed'); }
            this.log('    encrypt_asym, rv:  ' + rv);
        
            this.log('    encrypt_asym, bufOut.length:  ' + bufOut.length);
            this.log('    encrypt_asym, bufOut:  ' + bufOut);
            
            bufOut = cUchar2u8a(bufOut, bufOut.length);
            this.log('    encrypt_asym, bufOut.byteLength:  ' + bufOut.byteLength);
            
            this.log('<-- encrypt_asym()');
            this.log('====================================================\/\\');
            return bufOut;
        } catch (e) {
            this.log('    encrypt_asym:  ' + e);
            throw e;
        } finally {
            if (pubKey && !pubKey.isNull()) this.nss.SECKEY_DestroyPublicKey(pubKey);
        }
    },
    
    decrypt_asym:  function WC_decrypt_asym(args) {
        this.log('--> decrypt_asym()');
        var der_priv, rv, bufIn, bufInLen, modulus_len, bufOut, slot, privateKey, publicKey;
        try {
            // get private key
            slot = this.nss.PK11_GetInternalKeySlot();  // nss sample in c uses this
            // or slot = this.nss.PK11_GetInternalSlot();
            if (slot === null) { throw new Error('Couldnt find slot'); }
            der_priv = this.abx2SecItem(args.key.keyData);
            privateKey = new this.nss_t.SECKEYPrivateKey.ptr();
            this.log('----------------------------------------------------\\\/');
            this.log('    decrypt_asym, privateKey:  ' + privateKey);
            this.log('    decrypt_asym, about to PK11_ImportDERPrivateKeyInfoAndReturnKey...');
            var KU_ALL = 0xff;
            rv = this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey(
                    slot,                   // PK11SlotInfo *slot
                    der_priv.address(),     // SECItem *derPKI
                    null,                   // SECItem *nickname
                    null,                   // SECItem *publicValue
                    this.nss.PR_FALSE,      // PRBool isPerm
                    this.nss.PR_TRUE,       // PRBool isPrivate
                    KU_ALL,                 // unsigned int usage
                    privateKey.address(),   // SECKEYPrivateKey** privk
                    null);                  // void *wincx
            this.log('    decrypt_asym, privateKey:  ' + privateKey);
            if (rv) { throw new Error('decrypt_asym, Couldnt extract private key, rv:  ' + rv); }
            
            // prep input data
            bufInLen = args.buf.byteLength;
            this.log('    decrypt_asym, bufInLen:  ' + bufInLen);
            bufIn = abx2cUchar(args.buf);
            
            publicKey = this.nss.SECKEY_ConvertToPublicKey(privateKey);
            modulus_len = this.nss.SECKEY_PublicKeyStrength(publicKey);
            this.log('    decrypt_asym, modulus_len:  ' + modulus_len);

            // prep output buffer
            bufOut = new Uint8Array(modulus_len);
            for (var i = 0; i < modulus_len; i++) {
                bufOut[i] = 7;  // value doesn't matter, just something to see in logs
            }
            bufOut = abx2cUchar(bufOut);
            this.log('    decrypt_asym, bufOut.address():  ' + bufOut.address());
        
            var outLen = new ctypes.unsigned_int();
        
            rv = this.nss.PK11_PrivDecryptPKCS1(
                    privateKey,           // SECKEYPrivateKey *key
                    bufOut,               // unsigned char *data
                    outLen.address(),     // unsigned *outLen
                    modulus_len,          // unsigned int maxLen
                    bufIn,                // unsigned char *enc
                    bufInLen);            // unsigned encLen
            
            this.log('    decrypt_asym, rv:  ' + rv);
            this.log('    decrypt_asym, outLen:  ' + outLen.value);
            
            rv = new Uint8Array(outLen.value);
            for (var i = 0; i < outLen.value; i++) {
                rv[i] = bufOut[i];
            }
            this.log('    decrypt_asym, rv[' + rv.byteLength + ']:  ' + JSON.stringify(rv));
            this.log('----------------------------------------------------\/\\');
            this.log('<-- decrypt_asym()');
            return rv;
        } catch (e) {
            this.log('    decrypt_asym:  ' + e);
            throw e;
        } finally {
            if (privateKey && !privateKey.isNull()) this.nss.SECKEY_DestroyPrivateKey(privateKey);
        }
    },
    
    sign:  function WC_sign(args) {
        this.log('--> sign() ----------------------------------------------------\\\/');
        
        var slot, der_priv, privateKey, rv;
        try {
            // get private key
            slot = this.nss.PK11_GetInternalKeySlot();  // nss sample in c uses this
            // or slot = this.nss.PK11_GetInternalSlot();
            if (slot === null) { throw new Error('Couldnt find slot'); }
            der_priv = this.abx2SecItem(args.key.keyData);
            privateKey = new this.nss_t.SECKEYPrivateKey.ptr();
            this.log('    sign, privateKey:  ' + privateKey);
            this.log('    sign, about to PK11_ImportDERPrivateKeyInfoAndReturnKey...');
            var KU_ALL = 0xff;
            rv = this.nss.PK11_ImportDERPrivateKeyInfoAndReturnKey(
                    slot,                   // PK11SlotInfo *slot
                    der_priv.address(),     // SECItem *derPKI
                    null,                   // SECItem *nickname
                    null,                   // SECItem *publicValue
                    this.nss.PR_FALSE,      // PRBool isPerm
                    this.nss.PR_TRUE,       // PRBool isPrivate
                    KU_ALL,                 // unsigned int usage
                    privateKey.address(),   // SECKEYPrivateKey** privk
                    null);                  // void *wincx
            this.log('    sign, privateKey:  ' + privateKey);
            if (rv) { throw new Error('sign, Couldnt extract private key, rv:  ' + rv); }
            
            let hash = this.abx2SecItem(args.buf);
            let outputData = new ctypes.ArrayType(ctypes.unsigned_char, 0)();
            let sig = this.nss_t.SECItem(this.nss.SIBUFFER, outputData, outputData.length);
            sig.len = this.nss.PK11_SignatureLen(privateKey);
            sig.data = new ctypes.ArrayType(ctypes.unsigned_char, sig.len)();
            
            let status = this.nss.PK11_Sign(
                    privateKey,       // SECKEYPrivateKey *key
                    sig.address(),    // SECItem *sig
                    hash.address());  // SECItem *hash
            if (status === -1) { throw new Error('Could not sign message');
            } else { this.log('    sign, rv:  ' + status); }
            
            outputData = new Uint8Array(sig.len);
            let intData = ctypes.cast(sig.data, ctypes.uint8_t.array(sig.len).ptr).contents;
            for (let i = 0; i < sig.len; i++) {
                outputData[i] = intData[i];
            }
        
            this.log('<-- sign() ----------------------------------------------------\/\\');
            return outputData;
        } catch (e) {
            this.log('    sign:  ' + e);
            throw e;
        } finally {
            if (privateKey && !privateKey.isNull()) this.nss.SECKEY_DestroyPrivateKey(privateKey);
        }
    },
    
    verify:  function WC_verify(args) {
        this.log('--> verify() ====================================================\\\/');
        var der_pub, pubKeyInfo, pubKey;
        var sig, hash, result;
        
        try {
            // get public key
            der_pub = this.abx2SecItem(args.key.keyData);
            this.log('    verify, about to SECKEY_DecodeDER...');
            pubKeyInfo = this.nss.SECKEY_DecodeDERSubjectPublicKeyInfo(der_pub.address());
            if (pubKeyInfo.isNull()) { throw new Error("SECKEY_DecodeDERSubjectPublicKeyInfo failed"); }
            this.log('    verify, about to SECKEY_Extract...');
            pubKey = this.nss.SECKEY_ExtractPublicKey(pubKeyInfo);
            if (pubKey.isNull()) { throw new Error("SECKEY_ExtractPublicKey failed"); }
            this.log('    verify, pubKey:  ' + pubKey);
            
            sig = this.abx2SecItem(args.sig);
            hash = this.abx2SecItem(args.buf);

            result = this.nss.PK11_Verify(
                    pubKey,          // SECKEYPublicKey *key
                    sig.address(),   // SECItem *sig
                    hash.address(),  // SECItem *hash
                    null);           // void *wincx
            this.log('result:  ' + result);
            this.log('<-- verify() ====================================================\/\\');
        
            if (result == -1) {
                return false;
            }
            return true;
        } catch (e) {
            this.log('    verify:  ' + e);
            throw e;
        } finally {
            if (pubKey && !pubKey.isNull()) this.nss.SECKEY_DestroyPublicKey(pubKey);
        }
    },
    
    deriveKeyFromPassphrase: function WC_deriveKeyFromPassphrase (args) {
        // TODO call this from deriveKey()
        this.log("--> deriveKeyFromPassphrase(), args:  " + JSON.stringify(args));
        let salt = this.abx2SecItem(args.alg.salt);
        let pwd = this.abx2SecItem(args.alg.password);
        // Bug 436577 prevents us from just using SEC_OID_PKCS5_PBKDF2 here
        //let pbeAlg = this.algorithm;
        let pbeAlg = this.nss.SEC_OID_PKCS5_PBKDF2;
        let cipherAlg = 188;  // AES_256_CBC
        let prfAlg;
        switch (args.alg.prf) {
            case 'SHA-1':
                prfAlg = this.nss.SEC_OID_HMAC_SHA1; // callee picks if SEC_OID_UNKNOWN, but only SHA1 is supported
                break;
            default:
                this.log('    deriveKeyFromPassphrase(), prf not recognized');
                break;
        }

        // WeaveCrypto.js has:
        //     let keyLength  = keyLength || 0;    // 0 = Callee will pick.
        // For this code, that would translate to:
        let keyLength = args.alg.derivedKeyLen || 0;
        // For that, passing in 16 gives an output of 32 hex chars, passing in
        // 25 gives an error.  So, the rfc 6070 case 5 does not work.
        // Passing in 0 gives an output of 64 hex chars.
        
        let iterations = args.alg.iterations;

        let algid, slot, symKey, u8a;
        try {
            algid = this.nss.PK11_CreatePBEV2AlgorithmID(pbeAlg, cipherAlg, prfAlg,
                keyLength, iterations, salt.address());
            if (algid.isNull()) throw new Error("PK11_CreatePBEV2AlgorithmID failed");
            
            slot = this.nss.PK11_GetInternalSlot();
            if (slot.isNull()) throw new Error("couldn't get internal slot");

            symKey = this.nss.PK11_PBEKeyGen(slot, algid, pwd.address(), false, null);
            if (symKey.isNull()) throw new Error("PK11_PBEKeyGen failed");

            // Slightly odd API, this call just prepares the key value for
            // extraction, we get the actual bits from the call to PK11_GetKeyData().
            if (this.nss.PK11_ExtractKeyValue(symKey)) { throw new Error('PK11_PBEKeyGen failed.'); }
            symKeyData = this.nss.PK11_GetKeyData(symKey);
            if (symKeyData.isNull()) { throw new Error('PK11_GetKeyData failed.'); }
            
            u8a = new Uint8Array(symKeyData.contents.len);
            let intData = ctypes.cast(symKeyData.contents.data, ctypes.uint8_t.array(symKeyData.contents.len).ptr).contents;
            for (let i = 0; i < u8a.byteLength; ++i) {
                u8a[i] = intData[i];
            }
        } catch (e) {
            this.log("deriveKeyFromPassphrase: failed: " + e);
            throw e;
        } finally {
            if (algid && !algid.isNull()) this.nss.SECOID_DestroyAlgorithmID(algid, true);
            if (slot && !slot.isNull()) this.nss.PK11_FreeSlot(slot);
        }
        
        var importArgs = {keyType:  args.keyType,
                          extractable:  args.extractable,
                          alg:  args.alg,
                          keyUsages:  args.keyUsages,
                          format:  args.format,
                          keyData:  u8a};
        var key = this.importKey(importArgs);
        
        this.log("<-- deriveKeyFromPassphrase()");
        return key;
    },
    
    importKey: function WC_importKey (args) {
        this.log('--> importKey:  ' + JSON.stringify(args));
        var data =  new Uint8Array(args.keyData.buffer);
        this.log('    importKey, data:  ' + JSON.stringify(data));
        let rv = {
            type:  args.keyType,
            extractable:  args.extractable,
            algorithm:  args.alg,
            keyUsage:  args.keyUsages,
            format:  args.format,
            keyData:  abx2u8a(args.keyData),
        };
        
        return rv;
    },
    
    generateKey_sym: function WC_generateKey_sym (args) {
        this.log("--> generateKey_sym()");
        let keygenMech, keySize;

        this.log('JSON.stringify(args):  ' + JSON.stringify(args));
        
        // Does NSS have a lookup function to do this?
        switch (args.alg.name) {
            case 'AES-CTR':
            case 'AES-CBC':
            case 'AES-GCM':
                keygenMech = this.nss.CKM_AES_KEY_GEN;
                // WebCrypto uses bits.  NSS uses bytes.
                keySize = args.alg.length >> 3;
                break;
            default:
                throw new Error("unknown algorithm:  " + args.alg.name);
        }
        this.log('keygenMech:  ' + keygenMech);
        this.log('keySize:  ' + keySize);

        let slot, randKey, keydata;
        try {
            slot = this.nss.PK11_GetInternalSlot();
            if (slot.isNull()) throw new Error("couldn't get internal slot");

            randKey = this.nss.PK11_KeyGen(slot, keygenMech, null, keySize, null);
            if (randKey.isNull()) throw new Error("PK11_KeyGen failed.");

            // Slightly odd API, this call just prepares the key value for
            // extraction, we get the actual bits from the call to PK11_GetKeyData().
            if (this.nss.PK11_ExtractKeyValue(randKey)) throw new Error("PK11_ExtractKeyValue failed.");

            keydata = this.nss.PK11_GetKeyData(randKey);
            if (keydata.isNull()) throw new Error("PK11_GetKeyData failed.");

            let intData = ctypes.cast(keydata.contents.data, ctypes.uint8_t.array(keydata.contents.len).ptr).contents;
            
            this.log("<-- generateKey_sym()");
            let key = {
                type:  'secret',
                extractable:  args.extractable,
                algorithm:  args.alg.name,
                keyUsage:  args.keyUsages,
                keyData:  cUchar2u8a(intData, keydata.contents.len),
            }
            
            return key;
        } catch (e) {
            this.log("generateKey_sym failed: " + e);
            throw e;
        } finally {
            if (randKey && !randKey.isNull()) this.nss.PK11_FreeSymKey(randKey);
            if (slot && !slot.isNull()) this.nss.PK11_FreeSlot(slot);
        }
    },
    
    getRandomValues: function WC_getRandomValues (array) {
        this.log("--> generateRandomValues()");

        let bytes = this.generateRandomBytes(array.byteLength);
        
        let rv = null;
        if (array instanceof Int8Array) {
            log('got Int8');
            rv = new Int8Array(bytes.buffer);
        } else if (array instanceof Uint8Array) {
            log('got Uint8');
            rv = new Uint8Array(bytes.buffer);
        } else if (array instanceof Int16Array) {
            log('got Int16');
            rv = new Int16Array(bytes.buffer);
        } else if (array instanceof Uint16Array) {
            log('got Uint16');
            rv = new Uint16Array(bytes.buffer);
        } else if (array instanceof Int32Array) {
            log('got Int32');
            rv = new Int32Array(bytes.buffer);
        } else if (array instanceof Uint32Array) {
            log('got Uint32');
            rv = new Uint32Array(bytes.buffer);
        } else {
            this.log("<-- generateRandomValues()");
            return rv;
        }
        
        this.log("<-- generateRandomValues()");
        return rv;
    },
    
    generateRandomBytes: function WC_generateRandomBytes (byteCount) {
        this.log("--> generateRandomBytes()");

        let bytes = new ctypes.ArrayType(ctypes.unsigned_char, byteCount)();
        if (this.nss.PK11_GenerateRandom(bytes, byteCount)) {
            throw new Error("PK11_GenerateRandom failed");
        }

        this.log("<-- generateRandomBytes()");
        return cUchar2u8a(bytes, byteCount);
    },

    getAlgConst:  function WC_getAlgConst (alg, aKey) {
        this.log("--> getAlgConst()");
        let constant = 0;
        var keyData = abx2u8a(aKey.keyData);
        this.log('    getAlgConst, keyData.byteLength:  ' + keyData.byteLength);
        
        switch (alg.name) {
            case "AES-CBC":
                switch (keyData.byteLength) {
                    case 16:
                        constant = this.nss.AES_128_CBC;
                        break;
                    case 24:
                        constant = this.nss.AES_192_CBC;
                        break;
                    case 32:
                        constant = this.nss.AES_256_CBC;
                        break;
                }
                break;
            default:
                break;
        }
        
        this.log("<-- getAlgConst(), returning:  " + constant);
        return constant;
    },

    abx2SecItem:  function WC_abx2SecItem (input) {
        this.log("--> abx2SecItem()");
        let arr = abx2cUchar(input);
        let secItem = new this.nss_t.SECItem(this.nss.SIBUFFER, arr, arr.length);
        this.log("<-- abx2SecItem()");
        return secItem;
    },
};

// ---------- Utility functions ------------------------------------------------

// convert either an ArrayBuffer or an ArrayBufferView to Uint8Array
// if arg is neither, then throw
function abx2u8a (arg) {
    log("--> abx2u8a()");
    var u8a;
    if (arg.buffer === undefined) {
        if (arg.byteLength === undefined) {
            log('abx2u8a, expected AB or ABV, got type:  ' + typeof arg);
            throw new Error('In abx2u8a(), expected AB or ABV, got type:  ' + typeof arg);
        } else {
            u8a = new Uint8Array(arg);
        }
    } else {
        u8a = new Uint8Array(arg.buffer);
    }
    log("<-- abx2u8a, byteLength:  " + u8a.byteLength);
    return u8a;
}

function abx2cUchar (arg) {
    log("--> abx2cUchar()");
    var u8a = abx2u8a(arg);
        
    log('    abx2cUchar, u8a.byteLength:  ' + u8a.byteLength);
    let cArray = new ctypes.ArrayType(ctypes.unsigned_char)(u8a.byteLength);
    for (let i = 0; i < u8a.byteLength; ++i) {
        cArray[i] = u8a[i];
    }
    log("<-- abx2cUchar()");
    return cArray;
}

function cUchar2u8a (arr, len) {
    log("--> cUchar2u8a()");
    if (!len) {
        log('    cUchar2u8a, requires array length as 2nd arg');
        throw new Error('cUchar2u8a requires array length as 2nd arg');
    }
    let u8a = new Uint8Array(len);
    for (let i = 0; i < u8a.byteLength; ++i) {
        u8a[i] = arr[i];
    }
    log("<-- cUchar2u8a()");
    return u8a;
}
    
function str2u8a(str) {
    var u8a = new Uint8Array(str.length);
    for (var i=0; i<str.length; ++i) {
        u8a[i] = str.charCodeAt(i);
    }
    return u8a;
}

function abx2str(arg) {
    var u8a = abx2u8a(arg);
    var str = ""; 
    for (var i=0; i<u8a.length; ++i) {
        str += String.fromCharCode(u8a[i]);
    }   
    return str;
}

function abx2hex (arg) {
    //log('--> abx2hex');
    var u8a = abx2u8a(arg);
    var hex = "";
    for (var i = 0; i < u8a.length; ++i) {
        var zeropad = (u8a[i] < 0x10) ? "0" : "";
        hex += zeropad + u8a[i].toString(16);
    }
    //log('<-- abx2hex');
    return hex;
}

function hex2u8a (hex) {
    //log('--> hex2u8a');
    if (hex.length % 2 !== 0) {
        hex = "0" + hex;
    }

    var u8a = new Uint8Array(hex.length / 2);
    for (var i = 0; i < u8a.length; ++i) {
        u8a[i] = parseInt(hex.substr(2*i, 2), 16);
    }
    //log('<-- hex2u8a');
    return u8a;
}
