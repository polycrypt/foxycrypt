// uncomment a line to run its demo
function demo() {
    try {
        //demos.digest();
        //demos.generate_aes_gcm_192();
        demos.getRandomValues();
        //demos.import_decrypt();
        //demos.import_encrypt();
        //demos.import_export();
        //demos.import_encrypt_decrypt_rsa();
        //demos.import_sign_verify_rsa();
        //demos.derive_export();
    } catch (ex) {
        log(ex);
        throw ex;
    }
}

var demos = {
    import_sign_verify_rsa:  function import_sign_verify_rsa() {
        log('========== import_sign_verify_rsa');
        var opImportPublic, opImportPrivate, opSign, opVerify;
        var publicKey, privateKey;
        var alg = {
            name:  'RSASSA-PKCS1-v1_5',
            hash:  'sha-1',
        };
        
        var pub_hex = '30820122300d06092a864886f70d01010105000382010f003082010a0282010100c9d874ac9765832538b79e97657736a27e35910184aea98473ac7006fbd9230f81eea62181e001135b15708948dae2bbe1d4ae5a28d818dc837772edb708918117cb2858ae44ada6c89b73a299c583aced278cd1bc6e27292d36c865b32b17b3ccfaa1fb0d5f94f819a2edb787f3134896bc096b61f956f0e8407d26eb94f4e6004455081a25ac2d66c048485761c57ced57bca09c603d58d749d686936c669ab1c46879ced0ba41453350fd624426b82fdec19119c547b1f929db1f009b0a3d14467ef21c6eb568164ce935ae5aaee61384dd051f5fc05f422f65a1735f282c8d650e7d5f959fc318b557980facd7d913f69ce0c1c9553bbd698c915251f4f30203010001';
        var pub_abv = hex2abv(pub_hex);
        
        log('----- import public key()');
        try {
            opImportPublic = window.crypto.subtle.importKey('spki', pub_abv, alg, true, ['sign']);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        
        opImportPublic.oncomplete = function(evt) {
            log('--> opImportPublic.oncomplete');
            publicKey = opImportPublic.result;
            log('publicKey:  ' + JSON.stringify(publicKey));
            
            var priv_hex = '308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100c9d874ac9765832538b79e97657736a27e35910184aea98473ac7006fbd9230f81eea62181e001135b15708948dae2bbe1d4ae5a28d818dc837772edb708918117cb2858ae44ada6c89b73a299c583aced278cd1bc6e27292d36c865b32b17b3ccfaa1fb0d5f94f819a2edb787f3134896bc096b61f956f0e8407d26eb94f4e6004455081a25ac2d66c048485761c57ced57bca09c603d58d749d686936c669ab1c46879ced0ba41453350fd624426b82fdec19119c547b1f929db1f009b0a3d14467ef21c6eb568164ce935ae5aaee61384dd051f5fc05f422f65a1735f282c8d650e7d5f959fc318b557980facd7d913f69ce0c1c9553bbd698c915251f4f3020301000102820100326ae0e9e37f35bcec67e1334be2f540ad69cfe8a32dc5a61206b68ce8079adc5ac633b516edcf16f89f6856c25dfa5897d63a1ec729033cc191eaa13a20e7c7691c13dde2d9c0ce7239722ee15e16bff114f9f5c1ad7a16acf68c23eb170e7a98eed9db0dc21c41c4958fef520403831433afdea4c05559238a48389a8bc087e93b3d198f37f0237aedb89a679212e576e2f0bf83c346adce7bff208cf632559d34b21fc88dbe8178c86675fbe99dfcd2db54d7b802e9a590ae2de7ed57f3970ad58a104983fac8193eb18d969999acd1a790e6321b52512cf2da16cbc78e94f94a8fba52e71c382b167fcb075c2776e000ea85ca78ff6f9cc46dff7992860102818100efec5b8ef38ac6c79c808e9ac238ef02dab3c28bdd13bc1e9fb403484f89b04da99e95858308ab73092af3f282b0ff289c0bd0f98ad33a7bcf1098adf638be8d589b69e848262021dd89313c66317d98145ff3abce8ec675def9c054f17203e4b5248603f96848c33b3f8478de9f1b9ed95933c13b868a13cfc46e0e5ff4a07302818100d75ee9aa80207d315280b9c5199be5c744653dd1be99303c2b5bf022656f0fd15eef91c41e880c90e1750fd8730d029dbb8b020f2db2409f7fd5092c164d6360f0bc5d3a5092b44cb2131624c10ee27311ef7b723a3df80efe5f7a4c8273d84d19e8c132441825e00142fc7a20555898515336c9af80a90e072a88a28afeb98102818100ea99b07198bce3607e2ccac49313feca48b62b8e7daf756c7077221a8c03b3cc4d068f684cd7a66646d9a44e46f2f19d70f0b0f7c18288165644013761a2dcd8f3828c4da076ff467e0c4f83a2ddd3d4685fe6b1e1b9845fef9741350e1e91a60a665b50f988ba5584d2b82344744a1acaa6c9cfb1f7fd7e1fd41055a80858f7028181009e874e982217c80f361b6aa29a67168bc6dc7ed494e74d89fca07ff1d1981e9c8eb4e926e31261ad83471792cb9d17ffe2bc3f97cc9b18d64ed2111e528c444a66e93ff65cb89fde9475582755b40f1b84683305b1b94b8e3dcf29c6877f9e07a2baa0facf04b75c5b916326c20610608dfc22a7f27751f8f16d6d85b7aa280102818100a4bb2e0e98dfd132bf6eab037f4aa6d456a78bd083a0203f04ab0780e21a46815750907d7d50abe3f3ae790ea7f33eda1e30d1979be037e2e0c7eac8018dab4c34a8a732493ba4e20f94d80eea1adac4522584d0ed087f1aa9bcc35e0b24aceba23677433a8dc67645675e3d4f17fa3cf5381b79bf79195f05a3a5d81de752b4';
            var priv_abv = hex2abv(priv_hex);
            
            log('----- import private key()');
            try {
                opImportPrivate = window.crypto.subtle.importKey('pkcs8', priv_abv, alg, true, ['verify']);
            } catch (ex) {
                log(ex);
                throw ex;
            }
            
            opImportPrivate.oncomplete = function(evt) {
                log('--> opImportPrivate.oncomplete');
                privateKey = opImportPrivate.result;
                log('privateKey:  ' + JSON.stringify(privateKey));
            
                var bufToSign = hex2abv(t7_data);
                
                log('----- sign');
                try {
                    opSign = window.crypto.subtle.sign(alg, privateKey, bufToSign);
                } catch (ex) {
                    log(ex);
                    throw ex;
                }
                
                opSign.oncomplete = function(evt) {
                    log('--> opSign.oncomplete');
                    var sig = abv2hex(opSign.result);
                    log('sign typeof result:  ' + typeof sig);
                    log('sign result:  ' + JSON.stringify(sig));
                    
                    // uncomment this to alter the sig, and it should return 'false'
                    //sig = sig.slice(0, -1) + 'e';
                    
                    log('sign result:  ' + JSON.stringify(sig));
                    sig = hex2abv(sig);
                    
                    log('----- verify');
                    try {
                        opVerify = window.crypto.subtle.verify(alg, publicKey, sig, bufToSign);
                    } catch (ex) {
                        log(ex);
                        throw ex;
                    }
                    
                    opVerify.oncomplete = function(evt) {
                        log('--> opVerify.oncomplete');
                        var verified = opVerify.result;
                        log('    opVerify, result:  ' + verified);
                        log('<-- opVerify.oncomplete');
                    };
                    log('<-- opSign.oncomplete');
                };
                log('<-- opImportPrivate.oncomplete');
            };
            log('<-- opImportPublic.oncomplete');
        };
    },
    
    import_encrypt_decrypt_rsa:  function import_encrypt_decrypt_rsa() {
        log('========== import_encrypt_decrypt_rsa');
        var opImportPublic, opImportPrivate, opEncrypt, opDecrypt;
        var publicKey, privateKey;
        var alg = 'rsaes-pkcs1-v1_5';
        
        var pub_hex_from_params = params_to_spki_hex(t7_rsa_n, t7_rsa_e);
        var pub_hex_2048 = '30820122300d06092a864886f70d01010105000382010f003082010a0282010100c9d874ac9765832538b79e97657736a27e35910184aea98473ac7006fbd9230f81eea62181e001135b15708948dae2bbe1d4ae5a28d818dc837772edb708918117cb2858ae44ada6c89b73a299c583aced278cd1bc6e27292d36c865b32b17b3ccfaa1fb0d5f94f819a2edb787f3134896bc096b61f956f0e8407d26eb94f4e6004455081a25ac2d66c048485761c57ced57bca09c603d58d749d686936c669ab1c46879ced0ba41453350fd624426b82fdec19119c547b1f929db1f009b0a3d14467ef21c6eb568164ce935ae5aaee61384dd051f5fc05f422f65a1735f282c8d650e7d5f959fc318b557980facd7d913f69ce0c1c9553bbd698c915251f4f30203010001';
        var pub_hex_1024 = '30819f300d06092a864886f70d010101050003818d0030818902818100a18582bc8b95a44a58af77506df6da4eecc8c17ff0fca07d097ef93025dafb78cd00d534c170a30bb9ed33e7e1282555e8ebb72d2676779a0ba70cfc8ac71a398e8f46082104a3587393225b9b8f5490296472e90c914bea4b5654177cc21cb29f4231e7e4c89557779d16b9fb1106c63c2c49337a38b6d6a7643df0097330930203010001';
        //var pub_hex = pub_hex_from_params;
        var pub_hex = pub_hex_1024;
        //var pub_hex = pub_hex_2048;
        var pub_abv = hex2abv(pub_hex);
        
        log('----- import public key()');
        try {
            opImportPublic = window.crypto.subtle.importKey('spki', pub_abv, alg, true, ['encrypt']);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        
        opImportPublic.oncomplete = function(evt) {
            log('--> opImportPublic.oncomplete');
            publicKey = opImportPublic.result;
            log('publicKey:  ' + JSON.stringify(publicKey));
            
            var priv_hex_from_params = params_to_pkcs8_hex(t7_rsa_n, t7_rsa_e, t7_rsa_d);
            var priv_hex_2048 = '308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100c9d874ac9765832538b79e97657736a27e35910184aea98473ac7006fbd9230f81eea62181e001135b15708948dae2bbe1d4ae5a28d818dc837772edb708918117cb2858ae44ada6c89b73a299c583aced278cd1bc6e27292d36c865b32b17b3ccfaa1fb0d5f94f819a2edb787f3134896bc096b61f956f0e8407d26eb94f4e6004455081a25ac2d66c048485761c57ced57bca09c603d58d749d686936c669ab1c46879ced0ba41453350fd624426b82fdec19119c547b1f929db1f009b0a3d14467ef21c6eb568164ce935ae5aaee61384dd051f5fc05f422f65a1735f282c8d650e7d5f959fc318b557980facd7d913f69ce0c1c9553bbd698c915251f4f3020301000102820100326ae0e9e37f35bcec67e1334be2f540ad69cfe8a32dc5a61206b68ce8079adc5ac633b516edcf16f89f6856c25dfa5897d63a1ec729033cc191eaa13a20e7c7691c13dde2d9c0ce7239722ee15e16bff114f9f5c1ad7a16acf68c23eb170e7a98eed9db0dc21c41c4958fef520403831433afdea4c05559238a48389a8bc087e93b3d198f37f0237aedb89a679212e576e2f0bf83c346adce7bff208cf632559d34b21fc88dbe8178c86675fbe99dfcd2db54d7b802e9a590ae2de7ed57f3970ad58a104983fac8193eb18d969999acd1a790e6321b52512cf2da16cbc78e94f94a8fba52e71c382b167fcb075c2776e000ea85ca78ff6f9cc46dff7992860102818100efec5b8ef38ac6c79c808e9ac238ef02dab3c28bdd13bc1e9fb403484f89b04da99e95858308ab73092af3f282b0ff289c0bd0f98ad33a7bcf1098adf638be8d589b69e848262021dd89313c66317d98145ff3abce8ec675def9c054f17203e4b5248603f96848c33b3f8478de9f1b9ed95933c13b868a13cfc46e0e5ff4a07302818100d75ee9aa80207d315280b9c5199be5c744653dd1be99303c2b5bf022656f0fd15eef91c41e880c90e1750fd8730d029dbb8b020f2db2409f7fd5092c164d6360f0bc5d3a5092b44cb2131624c10ee27311ef7b723a3df80efe5f7a4c8273d84d19e8c132441825e00142fc7a20555898515336c9af80a90e072a88a28afeb98102818100ea99b07198bce3607e2ccac49313feca48b62b8e7daf756c7077221a8c03b3cc4d068f684cd7a66646d9a44e46f2f19d70f0b0f7c18288165644013761a2dcd8f3828c4da076ff467e0c4f83a2ddd3d4685fe6b1e1b9845fef9741350e1e91a60a665b50f988ba5584d2b82344744a1acaa6c9cfb1f7fd7e1fd41055a80858f7028181009e874e982217c80f361b6aa29a67168bc6dc7ed494e74d89fca07ff1d1981e9c8eb4e926e31261ad83471792cb9d17ffe2bc3f97cc9b18d64ed2111e528c444a66e93ff65cb89fde9475582755b40f1b84683305b1b94b8e3dcf29c6877f9e07a2baa0facf04b75c5b916326c20610608dfc22a7f27751f8f16d6d85b7aa280102818100a4bb2e0e98dfd132bf6eab037f4aa6d456a78bd083a0203f04ab0780e21a46815750907d7d50abe3f3ae790ea7f33eda1e30d1979be037e2e0c7eac8018dab4c34a8a732493ba4e20f94d80eea1adac4522584d0ed087f1aa9bcc35e0b24aceba23677433a8dc67645675e3d4f17fa3cf5381b79bf79195f05a3a5d81de752b4';
            //var priv_hex_1024 = '30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100a18582bc8b95a44a58af77506df6da4eecc8c17ff0fca07d097ef93025dafb78cd00d534c170a30bb9ed33e7e1282555e8ebb72d2676779a0ba70cfc8ac71a398e8f46082104a3587393225b9b8f5490296472e90c914bea4b5654177cc21cb29f4231e7e4c89557779d16b9fb1106c63c2c49337a38b6d6a7643df00973309302030100010281801c7a70c1938ecfc7b7f93ffd335639c97ea02ad5c70493bb58084621421b69093483f8137423caeb8f5d8e304d1789f5aaba9cb25e3cb6fbb7203dfeeced0be76041ea3f3bc2456637998b62e5a05402010fa03554075e9e855dad6724d1cc758893bca7e62913b2f4c800965b632908e70b33fbe9f79f1aaa365136425b10a1024100d3ebb1eba4cca3b26317409dfc8a17fc3f1d2053d8714609d1390d14ac3d6d335414866bd0c8c3287ad2f107505ef59ba233aae6c7129ae994fec7f0d9635443024100c31e2c33920d64279aab5c2e5e03513803da838bd3ab5741184bc92178d49795b104be9cc868432c40739fc921e652363b25538bdd51e8632c350b0528309571024100d2d80968ddca0c840b3ab33b7c6b187a0b813b0cb0a7e27b1a029d151858f530c052bb7ac17b3d5025038273386f82059a57b58d6e3b008dad83e001ad07ba690241009db8962259bd59686a2e7aa540798dfda99fc9160e544283ec0fd6d5a7c6b181df45e68ef5b0d21bc33db3bbf21b2bf98a75f1c2ed7478553236ee618ccb390102405f5d5a0a3493c43daa82bff8f22fea0974ad6cb8c405e8d0a90eb41a267510e298bb5c4de6fed6ba0c3ba304819cf4045f15b42e8199812a99d8c9279fd461e6';
            var priv_hex_1024 = '30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100a18582bc8b95a44a58af77506df6da4eecc8c17ff0fca07d097ef93025dafb78cd00d534c170a30bb9ed33e7e1282555e8ebb72d2676779a0ba70cfc8ac71a398e8f46082104a3587393225b9b8f5490296472e90c914bea4b5654177cc21cb29f4231e7e4c89557779d16b9fb1106c63c2c49337a38b6d6a7643df00973309302030100010281801c7a70c1938ecfc7b7f93ffd335639c97ea02ad5c70493bb58084621421b69093483f8137423caeb8f5d8e304d1789f5aaba9cb25e3cb6fbb7203dfeeced0be76041ea3f3bc2456637998b62e5a05402010fa03554075e9e855dad6724d1cc758893bca7e62913b2f4c800965b632908e70b33fbe9f79f1aaa365136425b10a1024100d3ebb1eba4cca3b26317409dfc8a17fc3f1d2053d8714609d1390d14ac3d6d335414866bd0c8c3287ad2f107505ef59ba233aae6c7129ae994fec7f0d9635443024100c31e2c33920d64279aab5c2e5e03513803da838bd3ab5741184bc92178d49795b104be9cc868432c40739fc921e652363b25538bdd51e8632c350b0528309571024100d2d80968ddca0c840b3ab33b7c6b187a0b813b0cb0a7e27b1a029d151858f530c052bb7ac17b3d5025038273386f82059a57b58d6e3b008dad83e001ad07ba690241009db8962259bd59686a2e7aa540798dfda99fc9160e544283ec0fd6d5a7c6b181df45e68ef5b0d21bc33db3bbf21b2bf98a75f1c2ed7478553236ee618ccb390102405f5d5a0a3493c43daa82bff8f22fea0974ad6cb8c405e8d0a90eb41a267510e298bb5c4de6fed6ba0c3ba304819cf4045f15b42e8199812a99d8c9279fd461e6';
            //var priv_hex = priv_hex_from_params;
            var priv_hex = priv_hex_1024;
            //var priv_hex = priv_hex_2048;
        log('[' + pub_hex_from_params.length + '] ' + pub_hex_from_params);
        log('[' + pub_hex_1024.length + '] ' + pub_hex_1024);
        log('[' + priv_hex_from_params.length + '] ' + priv_hex_from_params);
        log('[' + priv_hex_1024.length + '] ' + priv_hex_1024);
            var priv_abv = hex2abv(priv_hex);
            
            log('----- import private key()');
            try {
                opImportPrivate = window.crypto.subtle.importKey('pkcs8', priv_abv, alg, true, ['decrypt']);
            } catch (ex) {
                log(ex);
                throw ex;
            }
            
            opImportPrivate.oncomplete = function(evt) {
                log('--> opImportPrivate.oncomplete');
                privateKey = opImportPrivate.result;
                log('privateKey:  ' + JSON.stringify(privateKey));
            
                var bufToEncrypt = hex2abv(t7_data);
                
                log('----- encrypt');
                try {
                    opEncrypt = window.crypto.subtle.encrypt(alg, publicKey, bufToEncrypt);
                } catch (ex) {
                    log(ex);
                    throw ex;
                }
                
                opEncrypt.oncomplete = function(evt) {
                    log('--> opEncrypt.oncomplete');
                    var bufToDecrypt = abv2hex(opEncrypt.result);
                    log('encrypt typeof result:  ' + typeof bufToDecrypt);
                    log('encrypt result:  ' + JSON.stringify(bufToDecrypt));
                    bufToDecrypt = hex2abv(bufToDecrypt);
                    
                    log('----- decrypt');
                    try {
                        opDecrypt = window.crypto.subtle.decrypt(alg, privateKey, bufToDecrypt);
                    } catch (ex) {
                        log(ex);
                        throw ex;
                    }
                    
                    opDecrypt.oncomplete = function(evt) {
                        log('--> opDecrypt.oncomplete');
                        var decrypted = abv2hex(opDecrypt.result);
                        log('    opDecrypt, expected:  ' + abv2hex(bufToEncrypt));
                        log('    opDecrypt, received:  ' + decrypted);
                        log('<-- opDecrypt.oncomplete');
                    };
                    log('<-- opEncrypt.oncomplete');
                };
                log('<-- opImportPrivate.oncomplete');
            };
            log('<-- opImportPublic.oncomplete');
        };
    },
    
    import_encrypt:  function import_encrypt() {
        log('========== _import_ encrypt');
        var op;
        var format = 'raw';
        var keyData = hex2abv(t13_key);
        var algorithm = 'AES-CBC';
        var extractable = true;
        var keyUsages = [ 'encrypt', 'decrypt', ];
        
        log('call window.crypto.subtle.importKey()');
        try {
            op = window.crypto.subtle.importKey(format,
                                                keyData,
                                                algorithm,
                                                extractable,
                                                keyUsages);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        log('define oncomplete()');
        op.oncomplete = function (evt) {
            log('--> oncomplete');
            log(JSON.stringify(op.result));
            log('========== import _encrypt_');
            var op2;
            var alg = {
                name:  'AES-CBC',
                iv:  hex2abv(t13_iv),
            };
            var key = op.result;
            
            var buf = hex2abv(t13_data);
        
            log('call window.crypto.subtle.encrypt()');
            try {
                op2 = window.crypto.subtle.encrypt(alg, key, buf);
            } catch (ex) {
                log(ex);
                throw ex;
            }
            
            log('define oncomplete()');
            op2.oncomplete = function (evt) {
                log('--> oncomplete');
                var out = abv2hex(op2.result);
                log('&nbsp;&nbsp;result [' + out.length + ']:<br />  ' + out);
                log('expected [' + t13_result.length + ']:<br />  ' + t13_result);
                log('<-- oncomplete');
            };
            log('<-- oncomplete');
        };
    },
    
    import_decrypt:  function import_decrypt() {
        log('========== _import_ decrypt');
        var op;
        var format = 'raw';
        var keyData = hex2abv(t14_key);
        var algorithm = 'AES-CBC';
        var extractable = true;
        var keyUsages = [ 'encrypt', 'decrypt', ];
        
        log('call window.crypto.subtle.importKey()');
        try {
            op = window.crypto.subtle.importKey(format,
                                                keyData,
                                                algorithm,
                                                extractable,
                                                keyUsages);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        log('define oncomplete()');
        op.oncomplete = function (evt) {
            log('--> oncomplete');
            log(JSON.stringify(op.result));
            log('========== import _decrypt_');
            var op2;
            var alg = {
                name:  'AES-CBC',
                iv:  hex2abv(t14_iv),
            };
            var key = op.result;
            
            var buf = hex2abv(t14_data);
        
            log('call window.crypto.subtle.decrypt()');
            try {
                op2 = window.crypto.subtle.decrypt(alg, key, buf);
            } catch (ex) {
                log(ex);
                throw ex;
            }
            
            log('define oncomplete()');
            op2.oncomplete = function (evt) {
                log('--> oncomplete');
                var out = abv2hex(op2.result);
                log('&nbsp;&nbsp;result [' + out.length + ']:<br />  ' + out);
                log('expected [' + t14_result.length + ']:<br />  ' + t14_result);
                log('<-- oncomplete');
            };
            log('<-- oncomplete');
        };
    },
        
    import_export:  function import_export() {
        log('========== _import_ export');
        var op;
        var format = 'raw';
        var keyData = hex2abv('000102030405060708090a0b0c0d0e0f');
        var algorithm = 'AES-CBC';
        var extractable = true;
        var keyUsages = [ 'encrypt', 'decrypt', ];
        
        log('call window.crypto.subtle.importKey()');
        try {
            op = window.crypto.subtle.importKey(format,
                                                keyData,
                                                algorithm,
                                                extractable,
                                                keyUsages);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        op.oncomplete = function (evt) {
            log(JSON.stringify(op.result));
            log('========== import _export_');
            var op2;
            var format = 'raw';
            var key = op.result;
            log('call window.crypto.subtle.exportKey()');
            try {
                op2 = window.crypto.subtle.exportKey(format, key);
            } catch (ex) {
                log (ex);
                throw ex;
            }
            op2.oncomplete = function (evt) {
                log(JSON.stringify(op2.result));
                log('key data:  ' + abv2hex(op2.result.keyData));
            }
        };
    },
        
    derive_export:  function derive_export() {
        log('========== derive export');
        var op;
        var pbkdf2Params = {
                name:  'PBKDF2',
                salt:  hex2abv(t17_salt),
                iterations:  t17_c,
                derivedKeyLen:  t17_dkLen,
                derivedKeyType:  null,
                prf:  'SHA-1',
                password:  hex2abv(t17_data),
            };
        
        log('call window.crypto.subtle.deriveKey()');
        try {
            op = window.crypto.subtle.deriveKey(pbkdf2Params, null, 'symmetric', true, [ 'encrypt', 'decrypt', ]);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        
        log('define oncomplete()');
        op.oncomplete = function (evt) {
            log('--> oncomplete');
            var op2;
            var format = 'raw';
            var key = op.result;
            log('call window.crypto.subtle.exportKey()');
            try {
                op2 = window.crypto.subtle.exportKey(format, key);
            } catch (ex) {
                log (ex);
                throw ex;
            }
            op2.oncomplete = function (evt) {
                var keyData = abv2hex(op2.result.keyData);
                log('key data [' + keyData.length + ']:<br /> ' + keyData);
            
                log('expected [' + t17_result.length + ']:<br />  ' + t17_result);
                log('<-- oncomplete');
            }
        };
    },
        
    generate_aes_gcm_192:  function generate_aes_gcm_192() {
        log('========== generate_aes_gcm_192');
        var op;
        var alg = {
            name:  'AES-GCM',
            length:  192,
        }
        var extractable = true;
        var keyUsages = [ 'encrypt', 'decrypt', ];
        
        log('call window.crypto.subtle.generateKey()');
        try {
            op = window.crypto.subtle.generateKey(alg, extractable, keyUsages);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        
        log('define oncomplete()');
        op.oncomplete = function (evt) {
            log('--> oncomplete');
            log(JSON.stringify(evt.target.result));
            log('<-- oncomplete');
        };
    },
        
    digest:  function digest() {
        log('========== digest SHA-256');
        var op;
        var buf = hex2abv(hex_in);
        
        log('call window.crypto.subtle.digest()');
        try {
            op = window.crypto.subtle.digest("SHA-256", buf);
        } catch (ex) {
            log(ex);
            throw ex;
        }
        
        log('define oncomplete()');
        op.oncomplete = function (evt) {
            log('--> oncomplete()');
            log("result: " + abv2hex(op.result));
            log("expect: " + hex_out_expected.toLowerCase());
        };
    },
    
    getRandomValues:  function getRandomValues() {
        log('========== get random values');
        log('call window.crypto.getRandomValues()');
        var op;
        try {
            op = window.crypto.getRandomValues(new Int16Array(3));
        } catch (ex) {
            log (ex);
            throw ex;
        }
        
        log('define oncomplete()');
        op.oncomplete = function (evt) {
            log('length:  ' + op.result.length);
            var i, values = 'values:  ';
            for (i = 0; i < op.result.length; i++) {
                if (i === 0) {
                    label = '';
                } else {
                    label = ', ';
                }
                values += label + op.result[i];
            }
            log(values);
        }
    },
};

// ===== TEST VECTORS ==========================================================

// 3. SHA-256 digest
// From the NESSIE project <https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/Sha-2-256.unverified.test-vectors>, Set 1, vector# 5
var hex_in = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
var hex_out_expected = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1";

// 7. PKCS1_v1.5 encryption
// RSA test vectors <ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15crypt-vectors.txt>, Example 1.2
// NOTE: PKCS1_v1.5 encryption is randomized, so Test 7 is a round-trip encrypt/decrypt
//       Test 8 then verifies that decryption is correct, so by implication, so is encryption (sorta)
var t7_rsa_n    = "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb";
var t7_rsa_e    = "010001";
var t7_rsa_d    = "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1";
var t7_data     = "750c4047f547e8e41411856523298ac9bae245efaf1397fbe56f9dd5";

// 8. PKCS1_v1.5 decryption
// RSA test vectors <ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15crypt-vectors.txt>, Example 1.3
var t8_rsa_n    = "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb";
var t8_rsa_e    = "010001";
var t8_rsa_d    = "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1";
var t8_data     = "709c7d2d4598c96065b6588da2f89fa87f062d7241ef6595898f637ada57eae90173f0fb4bf6a91ebd96506907c853dacf208494be94d313a04185d474a907412effc3e024d07e4d09aa245fbcb130219bfa5de02d4f7e2ec9e62e8ad32dee5ff4d8e4cfecbc5033a1c2c61c5233ae16192a481d0075bfc7ce028212cd27bebe";
var t8_result   = "d94ae0832e6445ce42331cb06d531a82b1db4baad30f746dc916df24d4e3c2451fff59a6423eb0e1d02d4fe646cf699dfd818c6e97b051";

// 9. PKCS1_v1.5 sign (using SHA1)
// RSA test vectors <ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15sign-vectors.txt>, Example 1.2
var t9_rsa_n    = "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137";
var t9_rsa_e    = "010001";
var t9_rsa_d    = "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325";
var t9_data     = "851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b7e3530c4c233e2b5f8f71a1cca582d43ecc72b1bca16dfc7013226b9e";
var t9_sig      = "84fd2ce734ec1da828d0f15bf49a8707c15d05948136de537a3db421384167c86fae022587ee9e137daee754738262932d271c744c6d3a189ad4311bdb020492e322fbddc40406ea860d4e8ea2a4084aa98b9622a446756fdb740ddb3d91db7670e211661bbf8709b11c08a70771422d1a12def29f0688a192aebd89e0f896f8";

// 10. PKCS1_v1.5 verify (using SHA1)
// RSA test vectors <ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15sign-vectors.txt>, Example 1.3
var t10_rsa_n   = "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137";
var t10_rsa_e   = "010001";
var t10_data    = "a4b159941761c40c6a82f2b80d1b94f5aa2654fd17e12d588864679b54cd04ef8bd03012be8dc37f4b83af7963faff0dfa225477437c48017ff2be8191cf3955fc07356eab3f322f7f620e21d254e5db4324279fe067e0910e2e81ca2cab31c745e67a54058eb50d993cdb9ed0b4d029c06d21a94ca661c3ce27fae1d6cb20f4564d66ce4767583d0e5f060215b59017be85ea848939127bd8c9c4d47b51056c031cf336f17c9980f3b8f5b9b6878e8b797aa43b882684333e17893fe9caa6aa299f7ed1a18ee2c54864b7b2b99b72618fb02574d139ef50f019c9eef416971338e7d470";
var t10_sig     = "0b1f2e5180e5c7b4b5e672929f664c4896e50c35134b6de4d5a934252a3a245ff48340920e1034b7d5a5b524eb0e1cf12befef49b27b732d2c19e1c43217d6e1417381111a1d36de6375cf455b3c9812639dbc27600c751994fb61799ecf7da6bcf51540afd0174db4033188556675b1d763360af46feeca5b60f882829ee7b2";

// 13. AES CBC encrypt
// Test vector from RFC 3602, Case 2 <http://tools.ietf.org/html/rfc3602#section-5>
var t13_key     = "c286696d887c9aa0611bbb3e2025a45a";  // len = 16 bytes
var t13_iv      = "562e17996d093d28ddb3ba695a2e6f58";
var t13_data    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
var t13_result  = "d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1bcfd81022202366bde6dd260a15841a1";

// 14. AES CBC decrypt
// Test vector from RFC 3602, Case 4 <http://tools.ietf.org/html/rfc3602#section-5>
var t14_key     = "56e47a38c5598974bc46903dba290349";
var t14_iv      = "8ce82eefbea0da3c44699ed7db51b7d9";
var t14_data    = "c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da5578b8d04731041aa2d9787ca4a4fa3eef";
var t14_result  = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";

// 17. PBKDF2/SHA1 derive
// Test vector from RFC 6070, case 5 <http://tools.ietf.org/html/rfc6070>
var t17_data    = "70617373776f726450415353574f524470617373776f7264";
var t17_salt    = "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74";
var t17_dkLen   = 16;  //25;
var t17_c       = 4096;
var t17_result  = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";

// From http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf, F.2.5
var t20_key     = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
var t20_iv      = "000102030405060708090a0b0c0d0e0f";
var t20_data    = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
// need output that accounts for pkcs7 padding
var t20_result  = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";


// ===== CONVERT N,E,D TO SPKI, PKCS8 =========================================

function hex_u8 (num) {
    if (num !== parseInt(num.toString(10), 10)) {
        throw new Error("arg was not integer");
    }
    var hex = num.toString(16);
    while (hex.length < 2) {
        hex = "0" + hex;
    }

    return hex;
}

function hex_u16 (num) {
    if (num !== parseInt(num.toString(10), 10)) {
        throw new Error("arg was not integer");
    }
    var hex = num.toString(16);
    while (hex.length < 4) {
        hex = "0" + hex;
    }

    return hex;
}

function params_to_spki_hex(n, e) {
    var SPKIhex;
    var p1 = '30819F300D06092A864886F70D010101050003818D0030818902818100';
    var p2 = '0203';
    
    if (n.length === 256) {
        SPKIhex = p1 + n + p2 + e;
    }
    
    if (n.length === 512) {
        var Nenc = "0282" + hex_u16(n.length/2) + n;
        var Eenc = "02" + hex_u8(e.length/2) + e;
        var SPKenc = Nenc + Eenc;

        var SPKIpre = "300D06092A864886F70D0101010500" 
            + "0382" + hex_u16(SPKenc.length/2 + 5) + "00" 
            + "3082" + hex_u16(SPKenc.length/2) + SPKenc;

        SPKIhex = "3082" + hex_u16(SPKIpre.length/2) + SPKIpre;
    }
    
    return SPKIhex;
}

function params_to_pkcs8_hex(n, e, d) {
    var pkcs8_hex;
    var p1, p2, p3, p4, p5, empty512, empty1024, empty2048;
    
    if (n.length === 256) {
        p1 = '30820277020100300D06092A864886F70D0101010500048202613082025D02010002818100';
        p2 = '0203';
        p3 = '028180';
        p4 = '024100';
        p5 = '0240';
        //empty512  = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        empty512  = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
        pkcs8_hex = p1 + n +
                    p2 + e +
                    p3 + d +
                    p4 + empty512 +
                    p4 + empty512 +
                    p4 + empty512 +
                    p4 + empty512 +
                    p5 + empty512;
    }

    if (n.length === 512) {
        p1 = '308204BF020100300D06092A864886F70D0101010500048204A9308204A50201000282010100';
        p2 = '0203';
        p3 = '02820100';
        p4 = '028181';
        //empty1024 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        empty1024 = '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
        //empty2048 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        empty2048 = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
        pkcs8_hex = p1 + n +
                    p2 + e +
                    p3 + d +
                    p4 + empty2048 +
                    p4 + empty1024 +
                    p4 + empty1024 +
                    p4 + empty1024 +
                    p4 + empty1024 +
                    p4 + empty1024;
    }

    return pkcs8_hex;
}

function b64toabv(b64) {
    var hex = atob(b64);
    var s = 'hex (' + hex.length + '), ' + typeof hex + ': ';
    var abv = new Uint8Array(hex.length);
    for (var i = 0; i < hex.length; i++) {
        abv[i] = parseInt(hex.charCodeAt(i), 10);
        if (i < 16) {
            s += i + ': ' + parseInt(hex.charCodeAt(i), 10) + ', ';
        }
    }
    log(JSON.stringify(s));
    
    return abv;
}


// ===== UTIL ==================================================================

var log = function (msg) {
    document.getElementById("results").innerHTML += msg + "<br />";
};


function abv2hex (abv) {
    //log('--> abv2hex');
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

var base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
function binary_to_base64(input) {
    var ret = new Array();
    var i = 0;
    var j = 0;
    var char_array_3 = new Array(3);
    var char_array_4 = new Array(4);
    var in_len = input.length;
    var pos = 0;

    while (in_len--) {
        char_array_3[i++] = input[pos++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i <4) ; i++) {
                ret += base64_chars.charAt(char_array_4[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = 0;
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++) {
            ret += base64_chars.charAt(char_array_4[j]);
        }

        while ((i++ < 3)) {
            ret += '=';
        }
    }

    return ret;
}

function hex_to_base64(hex) {
    if (hex.length % 2) {
        throw new Error("hex string length is odd");
    }
    var binary = new Array();
    for (var i = 0; i < hex.length/2; i++) {
        var h = hex.substr(i * 2, 2);
        binary[i] = parseInt(h, 16);        
    }
    
    return binary_to_base64(binary);
} 