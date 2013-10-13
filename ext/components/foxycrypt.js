/**
 * For license terms, see license.txt.
 *
 * This file:
 *   - exposes the WebCrypto API to content js.
 *   - creates a closure to handle cryptographic operations, and returns a
 *     reference to the closure to content js.
 *
 * For more details, see README.md.
 */

let Cu = Components.utils;
let Ci = Components.interfaces;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

function log(aMessage) {
    dump("--- " + aMessage + "\n");
}

// Import CryptMethods from the jsm.
XPCOMUtils.defineLazyGetter(this, "crypto", function() {
    Cu.import("resource://ext/foxycrypt.jsm");
    return CryptMethods;
});

// Some enums shared with the jsm and the worker.
const OP_TYPE = {
    INITIALIZE:  'initialize',
    ENCRYPT:  'encrypt',
    DECRYPT:  'decrypt',
    SIGN:  'sign',
    VERIFY:  'verify',
    DIGEST:  'digest',
    GENERATE_KEY:  'generate_key',
    DERIVE_KEY:  'derive_key',
    IMPORT_KEY:  'import_key',
    EXPORT_KEY:  'export_key',
    GET_RANDOM_VALUES:  'get_random_values',
};
    
const KEY_TYPE = {
    SECRET:  'secret',
    PUBLIC:  'public',
    PRIVATE:  'private',
};

const KEY_FORMAT = {
    RAW:  'raw',
    PKCS8:  'pkcs8',
    SPKI:  'spki',
    JWK:  'jwk',
};


// Define and expose the Web Cryptography API to content JS.
function CryptoAPI() {}
CryptoAPI.prototype = {
    classID: Components.ID("{c8277fc1-445f-4ca2-a210-e905ace4957b}"),
    QueryInterface: XPCOMUtils.generateQI([Ci.nsIDOMGlobalPropertyInitializer,]),

    // Make WebCrypto API calls available to content JS.
    init: function CA_init(aWindow) {
        let that = this;

        this.window = XPCNativeWrapper.unwrap(aWindow);
        
        this.sandbox = Cu.Sandbox(this.window, {
                sandboxPrototype: this.window,
                wantXrays: false
        });
        
        crypto.init(KEY_FORMAT, KEY_TYPE, OP_TYPE);
        
        //this.winId = this.window.QueryInterface(Ci.nsIInterfaceRequestor).
        //        getInterface(Ci.nsIDOMWindowUtils).currentInnerWindowID;

        let api = {
            getRandomValues:  that.getRandomValues.bind(that),
            subtle:  {
                encrypt:      that.encrypt.bind(that),
                decrypt:      that.decrypt.bind(that),
                sign:         that.sign.bind(that),
                verify:       that.verify.bind(that),
                digest:       that.digest.bind(that),
                generateKey:  that.generateKey.bind(that),
                deriveKey:    that.deriveKey.bind(that),
                importKey:    that.importKey.bind(that),
                exportKey:    that.exportKey.bind(that),
                __exposedProps__: {
                    encrypt: "r",
                    decrypt: "r",
                    sign: "r",
                    verify: "r",
                    digest: "r",
                    generateKey: "r",
                    deriveKey: "r",
                    importKey: "r",
                    exportKey: "r",
                },
            },

            __exposedProps__: {
                getRandomValues: "r",
                subtle: "r",
            },
        };

        return api;
    },
    
    encrypt: function CA_encrypt (aAlg, aKey, aBuf) {
        log("--> encrypt()");
        
        //log('=============================');
        //if (this.window.document.baseURI) { log('baseURI:  '+ this.window.document.baseURI); }
        //if (this.window.document.URL) { log('URL:  '+ this.window.document.URL); }
        //if (this.window.document.documentURI) { log('documentURI:  '+ this.window.document.documentURI); }
        //if (this.window.document.location) { log('location:  '+ this.window.document.location); }
        //if (this.window.document.domain) { log('domain:  '+ this.window.document.domain); }
        //log('=============================');
        
        let algNormalized = normalizeAlgorithm(aAlg);
        let supports = ALG_DICT[algNormalized.name.toLowerCase()]['supports'];
        if ( supports.indexOf(OP_TYPE.ENCRYPT) === -1 ) {
            _throw(new NotSupportedError('for encrypt:  '+ JSON.stringify(aAlg)));
        }
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.ENCRYPT,
            alg:  algNormalized,
            key:  aKey,
            sandbox:  this.sandbox,
        });
        
        if (aBuf) {
            this.window.setTimeout(op.process, 0, aBuf);
            this.window.setTimeout(op.finish, 0);
        }
        
        log("<-- encrypt()");
        return op;
    },
    
    decrypt: function CA_decrypt (aAlg, aKey, aBuf) {
        log("--> decrypt()");
        
        let algNormalized = normalizeAlgorithm(aAlg);
        let supports = ALG_DICT[algNormalized.name.toLowerCase()]['supports'];
        if ( supports.indexOf(OP_TYPE.DECRYPT) === -1 ) {
            _throw(new NotSupportedError('for decrypt:  '+ JSON.stringify(aAlg)));
        }
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.DECRYPT,
            alg:  algNormalized,
            key:  aKey,
            sandbox:  this.sandbox,
        });
        
        if (aBuf) {
            this.window.setTimeout(op.process, 0, aBuf);
            this.window.setTimeout(op.finish, 0);
        }
        
        log("<-- decrypt()");
        return op;
    },
    
    sign:  function CA_sign (aAlg, aKey, aBuf) {
        log("--> sign()");
        
        let algNormalized = normalizeAlgorithm(aAlg);
        let supports = ALG_DICT[algNormalized.name.toLowerCase()]['supports'];
        if ( supports.indexOf(OP_TYPE.SIGN) === -1 ) {
            _throw(new NotSupportedError('for sign:  '+ JSON.stringify(aAlg)));
        }
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.SIGN,
            alg:  algNormalized,
            key:  aKey,
            sandbox:  this.sandbox,
        });
        
        if (aBuf) {
            var digestAlg = normalizeAlgorithm(aAlg.hash);
            log('    sign, digestAlg:  ' + JSON.stringify(digestAlg));
            let digestAlgSupports = ALG_DICT[digestAlg.name.toLowerCase()]['supports'];
            log('    sign, supports:  ' + JSON.stringify(digestAlgSupports));
            if ( digestAlgSupports.indexOf(OP_TYPE.DIGEST) === -1 ) {
                _throw(new NotSupportedError('for digest:  '+ JSON.stringify(digestAlg)));
            }
            
            let args = {
                alg:  digestAlg,
                buf:  aBuf,
            };
        
            var hash = crypto.digest(args, null, true);
            this.window.setTimeout(op.process, 0, hash);
            this.window.setTimeout(op.finish, 0);
        }
        
        log("<-- sign()");
        return op;
    },
    
    verify:  function CA_verify (aAlg, aKey, aSig, aBuf) {
        log("--> verify()");
        
        let algNormalized = normalizeAlgorithm(aAlg);
        let supports = ALG_DICT[algNormalized.name.toLowerCase()]['supports'];
        if ( supports.indexOf(OP_TYPE.VERIFY) === -1 ) {
            _throw(new NotSupportedError('for verify:  '+ JSON.stringify(aAlg)));
        }
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.VERIFY,
            alg:  algNormalized,
            key:  aKey,
            sig:  aSig,
            sandbox:  this.sandbox,
        });
        
        if (aBuf) {
            var digestAlg = normalizeAlgorithm(aAlg.hash);
            let digestAlgSupports = ALG_DICT[digestAlg.name.toLowerCase()]['supports'];
            if ( digestAlgSupports.indexOf(OP_TYPE.DIGEST) === -1 ) {
                _throw(new NotSupportedError('for digest:  '+ JSON.stringify(digestAlg)));
            }
            
            let args = {
                alg:  digestAlg,
                buf:  aBuf,
            };
        
            var hash = crypto.digest(args, null, true);
            this.window.setTimeout(op.process, 0, hash);
            this.window.setTimeout(op.finish, 0);
        }
        
        log("<-- verify()");
        return op;
    },
    
    generateKey: function CA_generateKey(aAlg, aExtractable, aKeyUsages) {
        log('--> generateKey()');
        
        let algNormalized = normalizeAlgorithm(aAlg);
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.GENERATE_KEY,
            alg:  algNormalized,
            extractable:  aExtractable || false,
            keyUsages:  aKeyUsages || [],
            sandbox:  this.sandbox,
            keyType:  this.determineKeyType(algNormalized),
        });
        
        this.window.setTimeout(op.process, 0);
        this.window.setTimeout(op.finish, 0);
        
        log("<-- generateKey()");
        return op;
    },
    
    deriveKey: function CA_deriveKey(aAlg, aBaseKey, aDerivedKeyType,
                                     aExtractable, aKeyUsages) {
        log('--> deriveKey()');
        
        let algNormalized = normalizeAlgorithm(aAlg);
        let supports = ALG_DICT[algNormalized.name.toLowerCase()]['supports'];
        if ( supports.indexOf(OP_TYPE.DERIVE_KEY) === -1 ) {
            _throw(new NotSupportedError('for deriveKey:  '+ JSON.stringify(aAlg)));
        }
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.DERIVE_KEY,
            alg:  algNormalized,
            baseKey:  aBaseKey || null,
            derivedKeyType:  aDerivedKeyType || null,
            extractable:  aExtractable || false,
            keyUsages:  aKeyUsages || [],
            sandbox:  this.sandbox,
        });
        
        this.window.setTimeout(op.process, 0);
        this.window.setTimeout(op.finish, 0);
        
        log("<-- deriveKey()");
        return op;
    },
    
    determineKeyType:  function CA_determineKeyType(alg, format) {
        log('--> determineKeyType');
        let rv = '';
        
        if (alg.name.slice(0,3) === 'AES') { rv = KEY_TYPE.SECRET; }
        
        if (alg.name.slice(0,3) === 'RSA') {
            if (format === KEY_FORMAT.PKCS8) { rv = KEY_TYPE.PRIVATE; }
            if (format === KEY_FORMAT.SPKI) { rv = KEY_TYPE.PUBLIC; }
        }
        
        if (rv === '') {
            log('Error:  KEY_TYPE not defined for algorithm:  ' + alg.name);
            throw new Error('KEY_TYPE not defined for algorithm:  ' + alg.name);
        }
        
        log('<-- determineKeyType');
        return rv;
    },
    
    importKey: function CA_importKey(format, keyData, aAlg, extractable, keyUsages) {
        log('--> importKey()');
        
        let algNormalized = normalizeAlgorithm(aAlg);
        
        let keyType = this.determineKeyType(algNormalized, format);
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.IMPORT_KEY,
            alg:  algNormalized,
            format:  format,
            keyData:  keyData,
            keyType:  keyType,
            extractable:  extractable || false,
            keyUsages:  keyUsages || [],
            sandbox:  this.sandbox,
        });
        
        this.window.setTimeout(op.process, 0);
        this.window.setTimeout(op.finish, 0);
        
        log('<-- importKey()');
        return op;
    },
    
    exportKey: function CA_exportKey(format, key) {
        log('--> exportKey()');
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.EXPORT_KEY,
            format:  format,
            key:  key,
            sandbox:  this.sandbox,
        });
        
        this.window.setTimeout(op.process, 0);
        this.window.setTimeout(op.finish, 0);
        
        log('<-- exportKey()');
        return op;
    },
    
    digest: function CA_digest (aAlg, aBuf) {
        log("--> digest()");
        
        let algNormalized = normalizeAlgorithm(aAlg);
        let supports = ALG_DICT[algNormalized.name.toLowerCase()]['supports'];
        if ( supports.indexOf(OP_TYPE.DIGEST) === -1 ) {
            _throw(new NotSupportedError('for digest:  '+ JSON.stringify(aAlg)));
        }
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.DIGEST,
            alg:  algNormalized,
            sandbox:  this.sandbox,
        });

        if (aBuf) {
            this.window.setTimeout(op.process, 0, aBuf);
            this.window.setTimeout(op.finish, 0);
        }
        
        log("<-- digest()");
        return op;
    },
    
    getRandomValues: function CA_getRandomValues(array) {
        log('--> getRandomValues()');
        
        /*
        var test = new Int16Array(3) instanceof Int16Array;
        log('***** test:  ' + test);  // true
        log('***** typeof array:  ' + typeof array);  // object
        log('***** array instanceof Int16Array:  ' + (array instanceof Int16Array));  // false
        log('*****');
        
        var isTypedArray = array instanceof Int8Array ||
                           array instanceof Uint8Array ||
                           array instanceof Int16Array ||
                           array instanceof Uint16Array ||
                           array instanceof Int32Array ||
                           array instanceof Uint32Array;
        if (!isTypedArray) {
            log('    getRandomValues, Error:  argument must be typed array object type');
            _throw(new TypeMismatchError('argument must be typed array object type'));
        }
        */
        
        if (array.byteLength > 65536) {
            log('    getRandomValues, Error:  arg.byteLength > 65536 not allowed');
            _throw(new QuotaExceededError('arg.byteLength > 65536 not allowed'));
        }
        
        log('    getRandomwValues, len:  ' + array.byteLength);
        log('    getRandomwValues, type:  ' + typeof array);
        log('    getRandomwValues, type[1]:  ' + typeof array[1]);
        
        let op = makeCryptoOperation({
            opType:  OP_TYPE.GET_RANDOM_VALUES,
            array:  array,
            sandbox:  this.sandbox,
        });
        
        this.window.setTimeout(op.process, 0);
        this.window.setTimeout(op.finish, 0);
        
        log('<-- getRandomValues()');
        return op;
    },
};


// Create a closure to encapsulate a crypto operation.
function makeCryptoOperation (args) {
    log("--> makeCryptoOperation()");
    var op = {};
    
    op.result = null;
    op.internalState = null;  // null, error, complete
    op.isCryptoOp = false;
    
    // see op.finish() and op.innerCallback() for the meaning and usage of these vars
    // It's a hack to get some calls to not be lost and to be executed in order.
    op.numActiveProcesses = 0
    op.isFinishCached = false;
    log('    makeCryptoOperation, numActiveProcesses:  ' + op.numActiveProcesses);
    
    op.opType = args.opType;
    op.algorithm = args.alg;
    op.sandbox = args.sandbox;
    switch (args.opType) {
        case OP_TYPE.ENCRYPT:
            op.key = args.key;
            op.isCryptoOp = true;
            break;
        case OP_TYPE.DECRYPT:
            op.key = args.key;
            op.isCryptoOp = true;
            break;
        case OP_TYPE.SIGN:
            op.key = args.key;
            op.isCryptoOp = true;
            break;
        case OP_TYPE.VERIFY:
            op.key = args.key;
            op.sig = args.sig;
            op.isCryptoOp = true;
            break;
        case OP_TYPE.DIGEST:
            op.isCryptoOp = true;
            break;
        case OP_TYPE.GENERATE_KEY:
            op.extractable = args.extractable;
            op.keyUsages = args.keyUsages;
            op.keyType = args.keyType;
            break;
        case OP_TYPE.DERIVE_KEY:
            op.baseKey = args.baseKey;
            op.derivedKeyType = args.derivedKeyType;
            op.extractable = args.extractable;
            op.keyUsages = args.keyUsages;
            break;
        case OP_TYPE.IMPORT_KEY:
            op.format = args.format;
            op.keyData = args.keyData;
            op.keyType = args.keyType;
            op.extractable = args.extractable;
            op.keyUsages = args.keyUsages;
            break;
        case OP_TYPE.EXPORT_KEY:
            op.format = args.format;
            op.key = args.key;
            break;
        case OP_TYPE.GET_RANDOM_VALUES:
            op.array = args.array;
            break;
        default:
            log("    makeCryptoOperation, error:  unexpected CryptoOperation type:  '" + args.opType) + "'";
            break;
    }
    
    // These op._onfoo allow content js to read,write these functions.
    op._onabort = undefined;
    let onabortDescriptor = {
        enumerable:  true,
        configurable:  false,
        get:  function () { return op._onabort.toString(); },
        set:  function (x) { op._onabort = x; },
    };
    Object.defineProperty(op, "onabort", onabortDescriptor);
        
    op._onerror = undefined;
    let onerrorDescriptor = {
        enumerable:  true,
        configurable:  false,
        get:  function () { return op._onerror.toString(); },
        set:  function (x) { op._onerror = x; },
    };
    Object.defineProperty(op, "onerror", onerrorDescriptor);
        
    op._onprogress = undefined;
    let onprogressDescriptor = {
        enumerable:  true,
        configurable:  false,
        get:  function () { return op._onprogress.toString(); },
        set:  function (x) { op._onprogress = x; },
    };
    Object.defineProperty(op, "onprogress", onprogressDescriptor);

    op._oncomplete = undefined;
    let oncompleteDescriptor = {
        enumerable:  true,
        configurable:  false,
        get:  function () { return op._oncomplete.toString(); },
        set:  function (x) { op._oncomplete = x; },
    };
    Object.defineProperty(op, "oncomplete", oncompleteDescriptor);
    
    // This callback is passed to the jsm.
    op.innerCallback = function innerCallback (result) {
        log("--> innerCallback()");
        if (result.errorOccurred) {
            op.internalState = 'error';
            if (op._onerror) {
                var evt = { target: { result: op.result } };
                op.__exposedProps__[evt] = 'r';
                exposeChildren(evt);
                
                log("    innerCallback, call onerror");
                let sb = op.sandbox;
                sb.run = op._onerror;
                Cu.evalInSandbox(sb.run(evt), sb, '1.8', 'webcrypt.js', 1);
            }
        } else {
            log("    innerCallback, set op.result:  " + typeof result);
            op.result = result;
        
            log("    innerCallback, call onprogress");
            if (op.isCryptoOp && op._onprogress) {
                var evt = { target: { result: op.result } };
                op.__exposedProps__[evt] = 'r';
                exposeChildren(evt);
                
                let sb = op.sandbox;
                sb.run = op._onprogress;
                Cu.evalInSandbox(sb.run(evt), sb, '1.8', 'webcrypt.js', 1);
            }
        }
        op.numActiveProcesses -= 1;
        log('    innerCallback, numActiveProcesses:  ' + op.numActiveProcesses);
        log('    innerCallback, isFinishCached:  ' + op.isFinishCached);
        if (op.isFinishCached === true) {
            log('    innerCallback, call _finish');
            op._finish();
        }
        log("<-- innerCallback()");
    };
    op.innerCallback.bind(op);
    
    // Collect the correct args and callback.  Send a request to the jsm.
    op.process = function process (aBuf) {
        log("--> process()");
        if (op.internalState === 'error') {
            _throw(new InvalidStateError("process() called with internal state = error"));
        }
        
        op.numActiveProcesses += 1;
        log('    process, numActiveProcesses:  ' + op.numActiveProcesses);
        var args, isDigest = false;
        switch (op.opType) {
            case OP_TYPE.ENCRYPT:
                args = { alg: op.algorithm, key: op.key, buf: aBuf, opType: op.opType};
                break;
            case OP_TYPE.DECRYPT:
                args = { alg: op.algorithm, key: op.key, buf: aBuf, opType: op.opType};
                break;
            case OP_TYPE.SIGN:
                args = { alg: op.algorithm, key: op.key, buf: aBuf, opType: op.opType};
                break;
            case OP_TYPE.VERIFY:
                args = { alg: op.algorithm, key: op.key, sig: op.sig, buf: aBuf, opType: op.opType};
                break;
            case OP_TYPE.DIGEST:
                isDigest = true;
                args = { alg: op.algorithm, buf: aBuf, opType: op.opType};
                log('    process, crypto.digest()');
                crypto.digest(args, op.innerCallback);
                break;
            case OP_TYPE.GENERATE_KEY:
                args = { alg: op.algorithm, extractable: op.extractable,
                    keyUsages: op.keyUsages, opType: op.opType, keyType: op.keyType, };
                break;
            case OP_TYPE.DERIVE_KEY:
                args = { alg: op.algorithm, baseKey: op.baseKey,
                    derivedKeyType: op.derivedKeyType, extractable: op.extractable,
                    keyUsages: op.keyUsages, opType: op.opType, };
                break;
            case OP_TYPE.IMPORT_KEY:
                args = { format: op.format, keyData: op.keyData, alg: op.algorithm, keyType: op.keyType,
                    extractable: op.extractable, keyUsages: op.keyUsages, opType: op.opType, };
                break;
            case OP_TYPE.EXPORT_KEY:
                args = { format: op.format, key: op.key, opType: op.opType, };
                break;
            case OP_TYPE.GET_RANDOM_VALUES:
                args = { array:  op.array, opType: op.opType, };
                break;
            default:
                log('    process, Error: operation type "' +op.opType+ '" not wired in?');
                break;
        }
        
        if (args && !isDigest) {
            log('    process, crypto.process()');
            crypto.process(args, op.innerCallback);
        }
        log("<-- process()");
    };
    
    op.finish = function finish () {
        log("--> finish()");
        if (op.numActiveProcesses === 0) {
            log('    finish, call _finish');
            op._finish();
        } else {
            log('    finish, set isFinishCached = true');
            op.isFinishCached = true;
        }
        log("<-- finish()");
    };
    
    op._finish = function _finish () {
        log("--> _finish()");
        if (op.internalState === 'error') {
            _throw(new InvalidStateError("_finish() called with internal state = error"));
        }
        op.internalState = 'complete';
        
        if (op._oncomplete) {
            var evt = { target: { result: op.result } };
            op.__exposedProps__[evt] = 'r';
            exposeChildren(evt);
                
            log("    _finish, call _oncomplete");
            let sb = op.sandbox;
            sb.run = op._oncomplete;
            Cu.evalInSandbox(sb.run(evt), sb, '1.8', 'webcrypt.js', 1);
        }
        
        log("<-- _finish()");
    };
    
    op.abort = function abort () {
        log("--> abort()");
        if (op.internalState === 'error') {
            _throw(new InvalidStateError("abort() called with internal state = error"));
        }
        
        // TODO:  abort processing data
        
        if (op.isCryptoOp && op._onabort) {
            var evt = { target: { result: op.result } };
            //__exposedProps__ = {evt:  'r'};
            op.__exposedProps__[evt] = 'r';
            exposeChildren(evt);
                
            log("    abort, call oncomplete");
            let sb = op.sandbox;
            sb.run = op._onabort;
            Cu.evalInSandbox(sb.run(), sb, '1.8', 'webcrypt.js', 1);
        }
        
        log("<-- abort()");
    };
    
    // Allow content js access to these vars.
    op.__exposedProps__ = {
        process: 'r',
        finish: 'r',
        abort: 'r',
        key: 'r',
        algorithm: 'r',
        result: 'r',
        onabort: 'rw',
        onerror: 'rw',
        onprogress: 'rw',
        oncomplete: 'rw',
    };
    
    log("<-- makeCryptoOperation()");
    return op;
}

// Allow content js access to the children of the first arg.
var exposeChildren = function exposeChildren (thing, aIndent) {
    log('--> exposeChildren():  ' + JSON.stringify(thing));
    if (quacksLikeAbv(thing) || quacksLikeArray(thing) ||
            typeof thing !== 'object') {
        log('<-- exposeChildren(), nothing to expose');
        return;
    }
    
    let indent = '    ';
    if (aIndent) { indent += aIndent; }
    
    let key, val, keys = [];
    for (key in thing) {
        keys.push(key);
        log('    exposeChildren, ' + indent + 'key:  ' + key);
    }
    
    thing.__exposedProps__ = {};
    for (key in keys) {
        try {
            log('    exposeChildren, ' + indent + 'expose:  ' + keys[key]);
            thing.__exposedProps__[keys[key]] = 'r';
        } catch (e) {
            log('    exposeChildren, ' + indent + e.name +':  '+ e.message +':  '+ keys[key]);
        }
    }
    
    for (key in keys) {
        try {
            key = keys[key];
            val = thing[key];
            if (quacksLikeArray(val)) {
                log('    exposeChildren, ' + indent + key +':  (quacksLikeArray)');
            } else if (quacksLikeAbv(val)) {
                log('    exposeChildren, ' + indent + key +':  (quacksLikeAbv)');
            } else if (typeof val === 'object') {
                log('    exposeChildren, ' + indent +'exposeChildren('+ key +')');
                exposeChildren(val, indent);
            } else {
                log('    exposeChildren, ' + indent + key +':  '+ val +'('+ typeof val +')');
            }
        } catch (e) {
            log('    exposeChildren, ' + indent + e.name +':  '+ e.message);
        }
    }
};


function quacksLikeArray (thing) {
    if ( thing.concat && thing.every && thing.filter && thing.pop &&
        thing.push && thing.slice && thing.shift && thing.unshift) {
        return true;
    }
    return false;
}

function quacksLikeAbv (thing) {
    if ( thing.buffer && typeof thing.length === 'number' && typeof thing.byteOffset === 'number') {
        return true;
    }
    return false;
}

// ===== Custom Exceptions =====================================================
function InvalidAlgorithmError (msg) {
    this.name = 'InvalidAlgorithmError';
    this.message = msg || '';
}
InvalidAlgorithmError.prototype = new Error();


function InvalidStateError (msg) {
    this.name = 'InvalidStateError';
    this.message = msg || '';
}
InvalidStateError.prototype = new Error();


function NotSupportedError (msg) {
    this.name = 'NotSupportedError';
    this.message = msg || '';
}
NotSupportedError.prototype = new Error();


function QuotaExceededError (msg) {
    this.name = 'QuotaExceededError';
    this.message = msg || '';
}
QuotaExceededError.prototype = new Error();


function TypeMismatchError (msg) {
    this.name = 'TypeMismatchError';
    this.message = msg || '';
}
TypeMismatchError.prototype = new Error();


function _throw (ex) {
        this.__exposedProps__ = { ex:  'r', };
        ex.__exposedProps__ = { name:  'r', message:  'r', };
        throw ex;
}

// ===== Algorithm Normalization ===============================================
const ALG_DICT = {
    'aes-cbc':  {
        name:  'AES-CBC',
        dict:  { name:  'AES-CBC', },
        supports:  [OP_TYPE.ENCRYPT, OP_TYPE.DECRYPT, OP_TYPE.GENERATE_KEY],
    },
    'aes-ctr':  {
        name:  'AES-CTR',
        dict:  { name:  'AES-CTR', },
        supports:  [OP_TYPE.ENCRYPT, OP_TYPE.DECRYPT, OP_TYPE.GENERATE_KEY],
    },
    'aes-gcm':  {
        name:  'AES-GCM',
        dict:  { name:  'AES-GCM', },
        supports:  [OP_TYPE.ENCRYPT, OP_TYPE.DECRYPT, OP_TYPE.GENERATE_KEY],
    },
    'pbkdf2': {
        name:  'PBKDF2',
        dict:  { name:  'PBKDF2', },
        supports:  [OP_TYPE.DERIVE_KEY],
    },
    'md2':  {
        name:  'MD2',
        dict:  { name:  'MD2', },
        supports:  [OP_TYPE.DIGEST],
    },
    'md5':  {
        name:  'MD5',
        dict:  { name:  'MD5', },
        supports:  [OP_TYPE.DIGEST],
    },
    'sha-1':  {
        name:  'SHA-1',
        dict:  { name:  'SHA-1', },
        supports:  [OP_TYPE.DIGEST],
    },
    'sha-256':  {
        name:  'SHA-256',
        dict:  { name:  'SHA-256', },
        supports:  [OP_TYPE.DIGEST],
    },
    'sha-384':  {
        name:  'SHA-384',
        dict:  { name:  'SHA-384', },
        supports:  [OP_TYPE.DIGEST],
    },
    'sha-512':  {
        name:  'SHA-512',
        dict:  { name:  'SHA-512', },
        supports:  [OP_TYPE.DIGEST],
    },
    'rsassa-pkcs1-v1_5':  {
        name:  'RSASSA-PKCS1-v1_5',
        dict:  { name:  'RSASSA-PKCS1-v1_5', },
        supports:  [OP_TYPE.SIGN, OP_TYPE.VERIFY, OP_TYPE.GENERATE_KEY],
    },
    'rsaes-pkcs1-v1_5':  {
        name:  'RSAES-PKCS1-v1_5',
        dict:  { name:  'RSAES-PKCS1-v1_5', },
        supports:  [OP_TYPE.ENCRYPT, OP_TYPE.DECRYPT, OP_TYPE.GENERATE_KEY],
    }
};

/* Deviating from the Jun 3 version of the editors draft as follows:
 * 4. For each key K in O with an associated value V:
 *     - If K === 'name'
 *           result[K] = ALG_DICT.V.dict.name
 *     - If K !== 'name' && V is an AlgId
 *           result[K] = normalizeAlgorithm(V)
 *       else
 *           result[K] = O[K]
 */
function normalizeAlgorithm (aAlg) {
    log('--> normalizeAlgorithm()');
    if (typeof aAlg !== 'string' && typeof aAlg !== 'object') {
        log('    given alg is neither string nor object');
        throw new InvalidAlgorithmError('given alg is neither string nor object');
    }
    let result = {};
    if (typeof aAlg === 'string') {
        if (!/^[\000-\176]*$/.test(aAlg)) {
            log("    normalizeAlgorithm, aAlg was string and had non-ascii char(s)");
            throw new SyntaxError('algorithm contained non-ascii char(s)');
        }
    
        aAlg = aAlg.toLowerCase();
        if (aAlg in ALG_DICT) {
            if ('dict' in ALG_DICT[aAlg]) {
                result = ALG_DICT[aAlg]['dict'];
                result = normalizeAlgorithm(result);
            } else {
                log('    no default dictionary for given algorithm');
                throw new InvalidAlgorithmError('no default dictionary for given algorithm');
            }
        } else {
            log('    given algorithm not known');
            throw new InvalidAlgorithmError('given algorithm not known');
        }
    } else {
        let K, V, tmp;
        for (K in aAlg) {
            log('    K is:  ' + K);
            if (K === 'name') {
                V = aAlg[K];
                if (V in ALG_DICT) {
                    tmp = ALG_DICT[V];
                    tmp = tmp.dict.name;
                } else {
                    tmp = V;
                }
                result[K] = tmp;
            }
            if (K !== 'name' && aAlg[K] in ALG_DICT) {
                result[K] = normalizeAlgorithm(aAlg[K]);
            } else {
                result[K] = aAlg[K];
            }
        }
    }
    
    log('<-- normalizeAlgorithm()');
    return result;
}


var NSGetFactory = XPCOMUtils.generateNSGetFactory([CryptoAPI]);

