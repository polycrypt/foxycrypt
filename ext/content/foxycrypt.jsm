/**
 * For license terms, see license.txt.
 *
 * This file:
 *   - handles the creation and storage of the Key Encryption Key (kek).
 *   - handles requests from foxycrypt.js, passes them to foxycrypt-worker.js,
 *     and returns the result to foxycrypt.js.
 *   - directly handles calls to digest().
 *
 * For more details, see README.md.
 */

let Cu = Components.utils;
let Ci = Components.interfaces;
let Cc = Components.classes;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");

var EXPORTED_SYMBOLS = ["CryptMethods"];

// We use NSS for the crypto ops, which needs to be initialized before
// use. By convention, PSM is required to be the module that
// initializes NSS. So, make sure PSM is initialized in order to
// implicitly initialize NSS.
Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);

// We can call ChromeWorkers from this JSM
XPCOMUtils.defineLazyGetter(this, "worker", function() {
    return new ChromeWorker("foxycrypt-worker.js");
});


function log(aMessage) {
    dump("+jsm: " + aMessage + "\n");
}

// These enums are filled in by a call to CryptMethods.init().
var KEY_FORMAT;
var KEY_TYPE;
var OP_TYPE = { INITIALIZE:  'initialize', };


// ----- CALLBACKS FROM WORKER -------------------------------------------------
var callbackId = 0;
var callbacks = {};

worker.onmessage = function CW_worker_onmessage(evt) {
    log('--> worker.onmessage(), evt.data.callbackId:  ' + evt.data.callbackId);
    log('    worker.onmessage, typeof callbacks[id]:  ' + typeof callbacks[evt.data.callbackId]);
    callbacks[evt.data.callbackId](evt.data.result);
    log('<-- worker.onmessage()');
};

worker.onerror = function CW_onerror(aError) {
    log("Worker Error: " + aError.message);
    log("Worker Error filename: " + aError.filename);
    log("Worker Error line no: " + aError.lineno);
};

// ----- PROCESS QUEUE ---------------------------------------------------------
// The processQueue is used to save CryptMethods.process() calls that are made
//   before the kek is available.
// XXX: Beware the race condition in handling this queue.
var processQueue = new Queue();
function handleProcessQueue() {
    log('--> handleProcessQueue()');
    var item = processQueue.dequeue();
    while (item !== undefined) {
    log('    handleProcessQueue(), dequeue optype=' + item.args.opType);
        process(item.args, item.callback);
        item = processQueue.dequeue();
    }
    log('<-- handleProcessQueue()');
}

// Forward a crypto command to the worker.
function process(args, callback) {
    log('--> jsm process()')
    let myCallbackId = ++callbackId;
    callbacks[myCallbackId] = callback;
    log('    jsm process(), to worker: optype=' +args.opType+ ', callback=' + myCallbackId);
    worker.postMessage( { args: args, callbackId: myCallbackId, kek: kek, } );
    log('<-- jsm process()')
}
    
// ----- CRYPT_METHODS ---------------------------------------------------------
// The methods in this object are exposed via the nsIDOMGlobalPropertyInitializer
var initCalled = false;
var CryptMethods = {
    init:  function CM_init(aKeyFormat, aKeyType, aOpType) {
        log('--> init()');
        if (initCalled) {
            log('<-- init already called, returning');
            return;
        } else {
            initCalled = true;
        }
        
        // populate enum definitions
        KEY_FORMAT = aKeyFormat;
        KEY_TYPE = aKeyType;
        OP_TYPE = aOpType;
        
        // get full path to NSS via js-ctypes
        let path = Services.dirsvc.get("GreD", Ci.nsILocalFile);
        let libName = ctypes.libraryName("nss3"); // platform specific library name
        path.append(libName);
        let fullPath = path.path;
    
        // init the worker
        let args = {
            opType:  OP_TYPE.INITIALIZE,
            keyFormatEnum:  aKeyFormat,
            keyTypeEnum:  aKeyType,
            opTypeEnum:  aOpType,
            nssPath:  fullPath,
        };
        // make sure worker is initialized before (potentially) using it to generate kek
        let myCallbackId = ++callbackId;
        callbacks[myCallbackId] = readConfigFromFile;
        log('    init, postMessage(init)');
        worker.postMessage( { args: args, callbackId: myCallbackId } );
        log('<-- init');
    },
    
    // This function handles all calls from foxycrypt.js; except init and digest.
    process:  function CM_process(args, callback) {
        log('--> process()');
        if (!kek) {
            log('    process(), enqueue optype=' + args.opType);
            processQueue.enqueue( { args: args, callback: callback } );
        } else {
            process(args, callback);
        }
        log('<-- process()');
    },
    
    // digest can return synchronously, or call a callback
    digest: function CW_digest(args, callback, returnSynchronously) {
        log('--> digest()');
        var buf, hasher, hash, i, hexstr;
        try {
            buf = new Uint8Array(args.buf.buffer, 0, args.buf.buffer.byteLength);
            hasher = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
            
            switch (args.alg.name) {
                case 'MD2':
                    log('    digest, using MD2');
                    hasher.init(hasher.MD2);
                    break;
                case 'MD5':
                    log('    digest, using MD5');
                    hasher.init(hasher.MD5);
                    break;
                case 'SHA-1':
                    log('    digest, using SHA-1');
                    hasher.init(hasher.SHA1);
                    break;
                case 'SHA-256':
                    log('    digest, using SHA-256');
                    hasher.init(hasher.SHA256);
                    break;
                case 'SHA-384':
                    log('    digest, using SHA-384');
                    hasher.init(hasher.SHA384);
                    break;
                case 'SHA-512':
                    log('    digest, using SHA-512');
                    hasher.init(hasher.SHA512);
                    break;
                default:
                    log('    digest, alg type not recognized:  ' + args.alg.name);
                    throw new Error('digest alg not recognized');
                    break;
            }
            
            log('    digest, about to update...');
            log('    digest, buf.length:  ' + buf.length);
            hasher.update(buf, buf.length);  // cant see buf.length or buf.byteLength
            log('    digest, about to finish...');
            hash = hasher.finish(false);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        
        // an alternate for getting the contents of the hash
        //var toHexString = function CW_toHexString(charCode) {
            //return ('0' + charCode.toString(16)).slice(-2);
        //};
        //hexstr = [toHexString(hash.charCodeAt(i)) for (i in hash)].join('');
        //log('    digest, hexstr:  ' + hexstr);
        
        // another alternate for getting the contents of the hash
        // change the call to finish:  finish(true)
        // var abv = base64DecToArr(hash);
    
        var bin2abv = function CW_bin2abv(bin) {
            var abv = new Uint8Array(bin.length);
            for (var i=0; i<bin.length; ++i) {
                abv[i] = bin.charCodeAt(i);
            }   
            return abv;
        };
        
        var abv = bin2abv(hash);
        log('<-- digest, abv.byteLength:  ' + abv.byteLength);
        if (returnSynchronously) {
            return abv;
        } else {
            callback(abv);
            return 0;
        }
    },
};

// ----- KEK -------------------------------------------------------------------
// The Key Encryption Key (kek) has the same structure as an unwrapped key.
// When the keyData is saved to persistent storage, it is converted from
//     binary to hex-string.
var kek;

function setKek(aKek) {
    log('--> setKek()');
    kek = {  // the global kek
        type:  aKek.type,
        extractable:  aKek.extractable,
        algorithm:  aKek.algorithm,
        keyUsage:  aKek.keyUsage,
        keyData:  typeof aKek.keyData === 'string' ? hex2abv(aKek.keyData) : aKek.keyData,
    };
    log('<-- setKek()');
}

function generateKekCallback(aKek) {
    log('--> generateKekCallback()');
    if (isValidKek(aKek)) {
        setKek(aKek);
        writeConfigToFile(aKek);
        handleProcessQueue();
    } else {
        log('    generateKekCallback, failed to generate kek');
        throw new Error('failed to generate kek');
    }
    log('<-- generateKekCallback()');
}

function generateKek() {
    log('--> generateKek()');
    let alg = {
        name:  'AES-CBC',
        length:  128,
    };
    let args = {
        alg:  alg,
        extractable:  false,
        keyUsages:  ['wrap', 'unwrap'],
        opType:  OP_TYPE.GENERATE_KEY,
    };

    let myCallbackId = ++callbackId;
    callbacks[myCallbackId] = generateKekCallback;
    worker.postMessage( { args: args, callbackId: myCallbackId } );
    log('<-- generateKek()');
}

function isValidKek(aKek) {
    log('--> isValidKek(), kek:  ' + JSON.stringify(aKek));
    
    if (!aKek) {
        log('<-- isValidKek(), kek is falsy');
        return false;
    }
    if (!aKek.hasOwnProperty('keyUsage') ||
            aKek.keyUsage.indexOf('wrap') === -1 ||
            aKek.keyUsage.indexOf('unwrap') === -1) {
        log('<-- isValidKek(), invalid keyUsage');
        return false;
    }
    if (!aKek.hasOwnProperty('extractable') || aKek.extractable !== false) {
        log('<-- isValidKek(), invalid extractable');
        return false;
    }
    if (!aKek.hasOwnProperty('algorithm')) {
        log('<-- isValidKek(), invalid algorithm');
        return false;
    }
    if (!aKek.hasOwnProperty('keyData')) {
        log('<-- isValidKek(), invalid keyData');
        return false;
    } else {
        let kd = aKek['keyData'];
        if (     (undefined !== kd.length && kd.length < 1) ||
                 (undefined !== kd.byteLength && kd.byteLength < 1) ) {
            log('<-- isValidKek(), invalid keyData');
            return false;
        }
    }
    log('<-- isValidKek(), true');
    return true;
}

// ----- CONFIG FILE -----------------------------------------------------------
var CONFIG_FILE_PATH = 'webcrypto.json';
var PROFILE_DIR = 'ProfD';

function writeConfigToFile(aKek) {
    log('--> writeConfigToFile()');
    if (!aKek) {
        log('    Warning:  writeConfigToFile, kek is null');
    }

    var kekForFile = {
        type:  aKek.type,
        extractable:  aKek.extractable,
        algorithm:  aKek.algorithm,
        keyUsage:  aKek.keyUsage,
        keyData:  typeof aKek.keyData === 'string' ? aKek.keyData : abv2hex(aKek.keyData),
    };
    let data = JSON.stringify(kekForFile);
    
    let file = FileUtils.getFile(PROFILE_DIR, [CONFIG_FILE_PATH], true);
    if (!file.exists()) {
        file.create(Ci.nsIFile.NORMAL_FILE_TYPE, 0600);
    }
    
    let foStream = Cc["@mozilla.org/network/file-output-stream;1"].
            createInstance(Ci.nsIFileOutputStream);

    // see:  https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIFileOutputStream
    // void init(in nsIFile file,
    //           in long ioFlags,  // 0x02 = open for write only, 0x08 = if ! file exists, create file, 0x20 = if file exists, truncate file
    //           in long permissions,  // gnu/linux permissions
    //           in long behaviorFlags);  // 1 = DEFER_OPEN
    foStream.init(file, 0x02 | 0x08 | 0x20, 0666, 0);
    let converter = Cc["@mozilla.org/intl/converter-output-stream;1"].
            createInstance(Ci.nsIConverterOutputStream);
    converter.init(foStream, "UTF-8", 0, 0);
    converter.writeString(data);
    converter.close();
    log('<-- writeConfigToFile()');
}

function readConfigFromFileCallback(aKek) {
    log('--> readConfigFromFileCallback()');
    if (isValidKek(aKek)) {
        setKek(aKek);
        handleProcessQueue();
    } else {
        if (null !== aKek) {
            log('    readConfigFromFileCallback, invalid kek');
        }
        
        log('    readConfigFromFileCallback, generateKek()');
        generateKek();
    }
    log('<-- readConfigFromFileCallback()');
}

function readConfigFromFile() {
    log('--> readConfigFromFile()');
    let file = FileUtils.getFile(PROFILE_DIR, [CONFIG_FILE_PATH], true);
    if (!file.exists()) {
        log('    readConfigFromFile, config file does not exist');
        readConfigFromFileCallback(null);
    } else {
        let consumeFileData = function WC_consumeFileData(inputStream, status) {
            if (!Components.isSuccessCode(status)) {
                log('    readConfigFromFile, could not read config file');
                readConfigFromFileCallback(null);
            } else {
                var data = NetUtil.readInputStreamToString(inputStream, inputStream.available());
                var kek = JSON.parse(data);
                readConfigFromFileCallback(kek);
            }
        };
    
        NetUtil.asyncFetch(file, consumeFileData);
    }
    log('<-- readConfigFromFile()');
}

// ----- UTIL ------------------------------------------------------------------
function abv2hex (aAbv) {
    //log('--> abv2hex');
    var abv = new Uint8Array(aAbv);
    var hex = "";
    for (var i = 0; i < abv.length; ++i) {
        var zeropad = (abv[i] < 0x10) ? "0" : "";
        hex += zeropad + abv[i].toString(16);
    }
    //log('<-- abv2hex');
    return hex;
}

function hex2abv (hex) {
    //log('--> hex2abv');
    if (hex.length % 2 !== 0) {
        hex = "0" + hex;
    }

    var abv = new Uint8Array(hex.length / 2);
    for (var i = 0; i < abv.length; ++i) {
        abv[i] = parseInt(hex.substr(2*i, 2), 16);
    }
    //log('<-- hex2abv');
    return abv;
}

/* ******************* Queue.js - A function to represent a queue **************
 * 
 * Created by Stephen Morley - http://code.stephenmorley.org/ - and released
 * under the terms of the CC0 1.0 Universal legal code:
 * 
 * http://creativecommons.org/publicdomain/zero/1.0/legalcode
 */

/* Creates a new queue. A queue is a first-in-first-out (FIFO) data structure -
 * items are added to the end of the queue and removed from the front.
 */
function Queue() {
    // initialise the queue and offset
    var queue  = [];
    var offset = 0;

    // Returns the length of the queue.
    this.getLength = function() {
        // return the length of the queue
        return (queue.length - offset);
    };

    // Returns true if the queue is empty, and false otherwise.
    this.isEmpty = function() {
        // return whether the queue is empty
        return (queue.length == 0);
    };

    // Enqueues the specified item. The parameter is:
    // item - the item to enqueue
    this.enqueue = function(item) {
        // enqueue the item
        queue.push(item);
    };

    // Dequeues an item and returns it. If the queue is empty then undefined is
    // returned.
    this.dequeue = function() {
        // if the queue is empty, return undefined
        if (queue.length == 0) return undefined;

        // store the item at the front of the queue
        var item = queue[offset];

        // increment the offset and remove the free space if necessary
        if (++ offset * 2 >= queue.length) {
            queue  = queue.slice(offset);
            offset = 0;
        }

        // return the dequeued item
        return item;
    };

    // Returns the item at the front of the queue (without dequeuing it). If the
    // queue is empty then undefined is returned.
    this.peek = function() {
        // return the item at the front of the queue
        return (queue.length > 0 ? queue[offset] : undefined);
    };
}
/* ***************************** end of Queue.js **************************** */

