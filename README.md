FoxyCrypt - A Firefox extension for the Web Cryptography API
============================================================

This project is a partial implementation of the W3C [Web Cryptography API](http://www.w3.org/TR/WebCryptoAPI/), including:

    crypto.getRandomValues()
    crypto.subtle.encrypt()
    crypto.subtle.decrypt()
    crypto.subtle.sign()
    crypto.subtle.verify()
    crypto.subtle.digest()
    crypto.subtle.generateKey()
    crypto.subtle.deriveKey()
    crypto.subtle.importKey()
    crypto.subtle.exportKey()

and these algorithms:

    AES-CBC
    PBKDF2
    MD2
    MD5
    SHA-1
    SHA-256, -384, -512
    RSASSA-PKCS1-v1_5
    RSAES-PKCS1-v1_5

WARNING:  you really should not use this extension to do cryptography.  There are many reasons for this.  The purpose of the extension is to demonstrate usage of the API.

FoxyCrypt is written to a mixture of editor's drafts and published versions of the API near late spring 2013.

## Install and Use

To create a new `.xpi` file, say if you've modified some code, find the latest instructions [here](https://developer.mozilla.org/en-US/docs/Extensions).

There is a `mkxpi.py` script included.  Depending on your setup, you may be able to run this script as-is to create an `.xpi` file for the extension.  Or, you can tweak the Python code for your needs.

Load the files in the `demo/` directory into the Firefox browser to demonstrate usage.

Note on text encodings:  you may see different output than you would see when working with ascii or utf-8.  Foxycrypt treats text as a simplified approximation of utf-16.

If you start Firefox from a terminal, you can see log messages there.

## Code Overview

### Abbreviations

* js - foxycrypt.js
* jsm - foxycrypt.jsm
* worker - foxycrypt-worker.jsm
* app - the html page using the API in foxycrypt.js

### Files

#### foxycrypt.js

* `CryptoAPI.prototype.init()`

    * exposes the API to the app
    * receives the initial call from the app:  `window.crypto.subtle.foo()`
    * does some arg checking, passes args to `makeCryptoOperation()`
    * returns an object reference to the app

* `makeCryptoOperation()`

    * creates a closure to encapsulate the crypto operation.  Once created, this closure is what communicates with other parts of the code to accomplish the purposes of the crypto operation.

* `exposeChildren()`

    * allows the app to see the contents of the result of a crypto operation.

* `normalizeAlgorithm()`

    * checks whether we can use the algorithm specified by the app to do what is requested

#### foxycrypt.jsm

* handles the creation and storage of the Key Encryption Key (KEK).
* directly handles `digest()` requests
* handles crypto requests from the js, passes them to the worker, and returns the result to the js

#### foxycrypt-worker.js

* handles requests from the js, via the jsm
* performs key (un)wrap
* uses js-ctypes to pass crypto calls to NSS.

### Sample Sequence

The app calls into the js, for example:

    var encryptOp = window.crypto.subtle.encrypt(algorithm, key, buffer);

The js bundles the arguments, using one of the functions in `CryptoAPI` and passes them to `makeCryptoOperation()`.  There an operation object (`op`) is created, returned to the app, and assigned to `encryptOp`.

In the js, the op uses `op.process()` to call into the jsm, for example:

    crypto.process(args, op.innerCallback);

The jsm passes the request to the worker, via postMessage.  The worker handles the the cryptographic aspect of the request, then returns a response to the jsm via postMessage.  The jsm passes this response back to the `op` via the callback that it supplied.  A function inside the `op` exposes the result of the operation to the app, then uses the app window's sandbox to call one of the functions:  `encryptOp.oncomplete()`, `encryptOp.onerror()`, etc.

### Details

Each app gets its own instance of the js.  Each `op` created for the app by the js is a separate object created by `makeCryptoOperation()`.  However, all apps and `op`s share a single jsm.

The js handles algorithm normalization.

When a result object is passed back to the js from the worker, the `exposeChildren()` function walks down the tree of the result object, and exposes the items it contains, so the app can have read access to them.

The js contains a dictionary that defines which algorithms the extension can recognize.  It also declares some enumerations that are passed to the jsm and to the worker during initialization.

The jsm is primarily a communication channel between the js and the worker.  The jsm receives most requests from the js with its `process()` function.  Digests are an exception.  These are handled inside the jsm, and not sent to the worker.

The jsm creates and maintains a KEK.  The first time the jsm runs, it uses the worker to generate a KEK and saves it to a file.  From then on, when the jsm is started up, it reads the KEK from the file.  The KEK is not exposed to the js or to the app.  When the jsm passes a request to a worker, it passes the KEK along.

The KEK operations in the previous paragraph, either generating or loading from file, are never done before the first request comes from the app through the js.  So, while the KEK is not yet present, any requests are enqueued.  Later, when the KEK is present, the queue is handled, and subsequent requests are sent directly to the worker, and not enqueued.  Note that there is a race condition at the transition from the queued requests to new requests.

## Credits:

* Justin Dolske - The portions of foxycrypt-worker.js that interface to NSS are either directly from his WeaveCrypto.js, or derived it.

* David Dahl - His DOMCrypt is the source for much of the code that links things together.  Examples:

    * exporting the API into the app
    * getting a reference to the app window's sandbox into the js
    * importing the jsm's CryptMethods into the js
    * communicating between the jsm and the worker

* Stephen Morley - I use his Queue.js verbatim in the jsm.

## Known Issues

* Key wrapping and unwrapping are not implemented to any wrap specification; rather, they are implemented as simple encryption and decryption.
* According to the spec, you should be able to call `op.process()` multiple times to add data to be processed, and possibly receive processed results for each call.  This implementation only handles a single call to `op.process()`.
* This is a partial implementation.  There are several consequence to that.  E.g. the error code you see might be what the spec calls for, or it might not be.

