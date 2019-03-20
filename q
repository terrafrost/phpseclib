[33mcommit 019d9b0c4107f9e2fda87b21617af1ff4a19df3d[m[33m ([m[1;36mHEAD -> [m[1;32mchacha20-test[m[33m, [m[1;31morigin/chacha20-test[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Tue Mar 19 11:16:18 2019 -0500

    ...

[33mcommit 334fffa725651b20ab78f48a0eb6fd8a2f66fc00[m
Author: terrafrost <terrafrost@php.net>
Date:   Tue Mar 19 11:15:31 2019 -0500

    Revert "..."
    
    This reverts commit 7ed7a9cb6ec05265722cec7b639f896d109ee880.

[33mcommit 7ed7a9cb6ec05265722cec7b639f896d109ee880[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Mar 18 09:10:35 2019 -0500

    ...

[33mcommit c2983089afc2eed161210409005b27660f107fe5[m[33m ([m[1;31morigin/chacha20[m[33m, [m[1;32mchacha20[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Mar 18 07:36:33 2019 -0500

    ...

[33mcommit 517703e776e0ecb9722f4d9de6d770dcd9c0abab[m[33m ([m[1;32mmaster[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Mar 18 06:59:00 2019 -0500

    add Salsa20 / ChaCha20 stream ciphers

[33mcommit 8ce392f21879d6d255a5b064e7ea99f69472fa34[m[33m ([m[1;31mupstream/master[m[33m, [m[1;31mphpseclib/master[m[33m, [m[1;31morigin/master[m[33m, [m[1;31morigin/HEAD[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Mar 16 09:41:06 2019 -0500

    SFTP: nlist() didn't return empty directories - now it does
    
    I view this as a BC breaking change so atm do not plan on
    backporting it to 1.0/2.0. eg. now, all subdirectories have . and
    .. as "files" whereas before they didn't

[33mcommit 47280b4e440f52b0cae16c25ac842240f7eb7a1f[m
Merge: 09fdd609 11cf67cf
Author: terrafrost <terrafrost@php.net>
Date:   Sun Mar 10 11:53:57 2019 -0500

    Merge branch '2.0'

[33mcommit 11cf67cf78dc4acb18dc9149a57be4aee5036ce0[m[33m ([m[1;31mupstream/2.0[m[33m, [m[1;31mphpseclib/2.0[m[33m, [m[1;31morigin/2.0[m[33m, [m[1;32m2.0[m[33m)[m
Merge: 529fcae7 849f9976
Author: terrafrost <terrafrost@php.net>
Date:   Sun Mar 10 11:53:45 2019 -0500

    Merge branch '1.0' into 2.0

[33mcommit 849f9976330e70cb7884fe44b9dbc962d2b4bd0c[m[33m ([m[1;33mtag: 1.0.15[m[33m, [m[1;31mupstream/1.0[m[33m, [m[1;31mphpseclib/1.0[m[33m, [m[1;31morigin/1.0[m[33m, [m[1;32m1.0[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Mar 10 11:51:38 2019 -0500

    1.0.15 release

[33mcommit 09fdd60931713b598ca240887b5494296532c7e4[m
Merge: 8a58f3fc 529fcae7
Author: terrafrost <terrafrost@php.net>
Date:   Sat Mar 9 18:43:35 2019 -0600

    Merge branch '2.0'

[33mcommit 529fcae7f6e0251611436c051b341c3cbef16a4f[m
Merge: 307f685c 7c894b2b
Author: terrafrost <terrafrost@php.net>
Date:   Sat Mar 9 18:42:54 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 7c894b2b99f57c0dddb54c0f1af87a1cd9383e5b[m
Author: Ulugbek Miniyarov <miniyarov@users.noreply.github.com>
Date:   Fri Mar 8 11:33:02 2019 +0300

    Fix x509 OpenSSL format when multiple OU's are present
    
    When formatting DN in OpenSSL format Multiple Organizational Unit Names (OU) in certificates throw `PHP Notice:  Undefined index: id-at-organizationalUnitName` and returned array only contains the last OU.

[33mcommit 8a58f3fcd51f7430e83712201112aa1600638256[m
Merge: 37df27a4 307f685c
Author: terrafrost <terrafrost@php.net>
Date:   Sat Mar 9 17:25:42 2019 -0600

    Merge branch '2.0'

[33mcommit 307f685cbc6c3b3fb517ea6631dd040cbac3604f[m
Merge: e706c549 84e23292
Author: terrafrost <terrafrost@php.net>
Date:   Sat Mar 9 17:20:49 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 84e232924988f27caa7611321a1d2401d6d0c142[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Mar 9 17:08:59 2019 -0600

    Hash: fix issues with the mode

[33mcommit e706c549c107b177593f00bf29e1af1a0bb881d2[m
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 08:36:16 2019 -0600

    Hash: adjustments for 2.0 branch

[33mcommit 07ffe647f71f2029a9307803e7705d98d82db3b3[m
Merge: 0bb37d28 492562e0
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 08:34:58 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 492562e0344e49dd8465482aa1ca4645c0df8c4f[m
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 08:34:33 2019 -0600

    Hash: fix issues with _computeKey

[33mcommit 37df27a4af3e5659e0d34b5db22ec8f27d213a2a[m
Merge: 4a920c36 0bb37d28
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 08:02:54 2019 -0600

    Merge branch '2.0'

[33mcommit 4a920c3690b9360c3616cc180d90d8c1607e6213[m
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 08:02:20 2019 -0600

    RSA: fix bad merge

[33mcommit 0bb37d2853c0c22a65faddaa6d35e171f5ae6287[m
Merge: ed975a27 ca76d391
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 07:30:33 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit ca76d3913faa5bfeceed5f0f1dd917066bceb44f[m
Author: terrafrost <terrafrost@php.net>
Date:   Fri Mar 8 07:27:04 2019 -0600

    RSA: protect against possible timing attacks during OAEP decryption

[33mcommit 604954cd09345e96c9fe38f77d84dd2e6d843dc0[m[33m ([m[1;31mmini/master[m[33m)[m
Merge: 496fcd18 ed975a27
Author: terrafrost <terrafrost@php.net>
Date:   Mon Mar 4 08:16:25 2019 -0600

    Merge branch '2.0'

[33mcommit ed975a270d7c5dca9d9be73f3b66beca0407eded[m[33m ([m[1;31mmini/2.0[m[33m)[m
Merge: 03d9efcb a276c2b0
Author: terrafrost <terrafrost@php.net>
Date:   Mon Mar 4 08:15:45 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit a276c2b073f5761761d3caff3ce1326e0117c2eb[m[33m ([m[1;31mmini/1.0[m[33m)[m
Author: Zachery Stuart <zstuart@barracuda.com>
Date:   Tue Feb 26 14:34:15 2019 -0500

    Call xml_parser_free and unset to avoid memory leaks

[33mcommit 496fcd18cded7af62828bf00cce02a774394f48b[m
Merge: 2ddcc1f8 03d9efcb
Author: terrafrost <terrafrost@php.net>
Date:   Sun Mar 3 18:42:47 2019 -0600

    Merge branch '2.0'

[33mcommit 03d9efcbc95e7ae60fd3d6512e58da0c08f98ff0[m
Merge: 926e43af fce6063d
Author: terrafrost <terrafrost@php.net>
Date:   Sun Mar 3 18:40:36 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit fce6063de6844904b0a3facf3ba63a17f6f7b69d[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Mar 3 18:38:57 2019 -0600

    SFTP: make it so get() can correctly handle out of order responses

[33mcommit 2ddcc1f88a276012631eaad42744e98b65eca4cb[m[33m ([m[1;31mzacherystuart/master[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Feb 24 22:10:37 2019 -0600

    Travis: allow failures on nightly

[33mcommit adc9a5d1897445a7d289df90016fe90bcb85d39e[m
Merge: ef0518a8 926e43af
Author: terrafrost <terrafrost@php.net>
Date:   Sun Feb 24 21:37:43 2019 -0600

    Merge branch '2.0'

[33mcommit 926e43af9d12cbd2510889ca370dd2c5d1e26726[m
Merge: 86b05c00 48b1c87f
Author: terrafrost <terrafrost@gmail.com>
Date:   Sun Feb 24 21:36:40 2019 -0600

    Merge pull request #1344 from bobvandevijver/patch-1
    
    Fixed RSA loadKey type hint

[33mcommit 48b1c87f4cea08d50a6454ef6fffab73673fad46[m
Author: Bob van de Vijver <bobvandevijver@users.noreply.github.com>
Date:   Fri Feb 22 10:37:16 2019 +0100

    Fixed RSA loadKey type hint

[33mcommit ef0518a84a4e8011f771c5a7ddd6347b31855f91[m
Merge: bf7b1630 86b05c00
Author: terrafrost <terrafrost@php.net>
Date:   Sun Feb 10 17:24:06 2019 -0600

    Merge branch '2.0'

[33mcommit 86b05c00817710c61074bbeb4dee44cd9dc126c6[m
Merge: 9902edfa fcfba38f
Author: terrafrost <terrafrost@php.net>
Date:   Sun Feb 10 17:20:21 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit fcfba38fc7edf5322a44d934f81dac84f4c256c2[m[33m ([m[1;31mzacherystuart/1.0[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Feb 10 17:18:40 2019 -0600

    Crypt: avoid bogus IV errors in ECB mode

[33mcommit bf7b1630ea92f5145d0552a0150d0dc6e47ea7c4[m
Merge: ee742d4e 41c76d6e
Author: terrafrost <terrafrost@php.net>
Date:   Wed Feb 6 06:27:14 2019 -0600

    Merge branch 'master' of https://github.com/phpseclib/phpseclib

[33mcommit ee742d4edb69502ff6d1df2f935b5899ad2e4423[m
Merge: c03753e3 9902edfa
Author: terrafrost <terrafrost@php.net>
Date:   Tue Feb 5 23:31:20 2019 -0600

    Merge branch '2.0'

[33mcommit 9902edfac3071a7cd3ee7a8bc1fbba1a27a1f253[m
Merge: 0926c428 9a0a9a00
Author: terrafrost <terrafrost@php.net>
Date:   Tue Feb 5 23:31:04 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 9a0a9a009669f2d7496b0361653d94c6afedc259[m
Author: Alex Bouma <me@alexbouma.me>
Date:   Tue Feb 5 21:52:39 2019 +0100

    Whitelist OID 1.3.6.1.4.1.11129.2.4.2
    
    This OID is used in some intermediate certificates from the Dutch government and allows for parsing and saving/validating these certificates with phpseclib.

[33mcommit 41c76d6e0eff7a68785d0531783cb656ceefe89f[m[33m ([m[1;31mstayallive/master[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 17:10:06 2019 -0600

    SCP: replace user_error with exception

[33mcommit 0f3cbce359c351c1f52c9c72e9b26d9b86f6bded[m
Merge: 9e8afe2d 0926c428
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 17:04:49 2019 -0600

    Merge branch '2.0'

[33mcommit 0926c4286ec8cbf2347b69c568666f2ed4e296f9[m[33m ([m[1;31mstayallive/2.0[m[33m)[m
Merge: 8ebfcadb 5b795c18
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 17:04:12 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 5b795c18ab91f7809a0d6501a6feafbe5aa9921e[m[33m ([m[1;31mstayallive/1.0[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 17:03:53 2019 -0600

    SCP: issue error if remote_file is empty in put() call

[33mcommit 9e8afe2d78024be7ed1fbad6454efcec6fee8012[m
Merge: 590c92b2 8ebfcadb
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 13:37:47 2019 -0600

    Merge branch '2.0'

[33mcommit 8ebfcadbf30524aeb75b2c446bc2519d5b321478[m[33m ([m[1;33mtag: 2.0.14[m[33m)[m
Merge: 5c5a8a5c 7432a695
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 13:37:29 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 7432a6959afe98b9e93153d0034b0f62ad890d31[m[33m ([m[1;33mtag: 1.0.14[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 27 13:35:10 2019 -0600

    1.0.14 release

[33mcommit 590c92b2a1e2555a933120f41f9c7cff728533c4[m
Merge: c03753e3 5c5a8a5c
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 20 09:39:44 2019 -0600

    Merge branch '2.0'

[33mcommit 5c5a8a5c09acbdbae8d9b16ddc788af394e16304[m
Merge: 004a71ce 0f87a0e0
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 20 09:39:34 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 0f87a0e026cec9b758508840b193d71d8166f5e5[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 20 09:39:12 2019 -0600

    SSH2: CS adjustment

[33mcommit c03753e3c767cdebe209dfcd020205b63dc73ee3[m
Merge: ea3c8dbd 004a71ce
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 20 09:17:57 2019 -0600

    Merge branch '2.0'

[33mcommit 004a71ce194333b6c197e5606773cb6af96153b6[m
Merge: f8ff1aa2 e5ff894d
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 20 09:15:53 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit e5ff894d4b9d9eb1974ba32c878540aebad3aa0c[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Jan 20 09:12:43 2019 -0600

    SSH2: add missing constant

[33mcommit ea3c8dbd9a07d0ae295e61876a1024ba88111f47[m
Merge: 3f6eb201 f8ff1aa2
Author: terrafrost <terrafrost@php.net>
Date:   Wed Jan 16 21:17:18 2019 -0600

    Merge branch '2.0'

[33mcommit f8ff1aa27f573dc44180264f1f011b053ac5f467[m
Merge: 31fbdb96 b0d63fbf
Author: terrafrost <terrafrost@php.net>
Date:   Wed Jan 16 21:16:17 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit b0d63fbfb56222b3b14bc35aa6f6198b3b326d44[m
Author: terrafrost <terrafrost@php.net>
Date:   Wed Jan 16 21:15:11 2019 -0600

    SSH2: ssh-rsa is sometimes incorrectly used instead of rsa-sha2-256

[33mcommit 3f6eb2012ade2ec2982a502bf4d386ab69cea6b1[m
Merge: 44a56b8a 31fbdb96
Author: terrafrost <terrafrost@php.net>
Date:   Tue Jan 15 23:50:33 2019 -0600

    Merge branch '2.0'

[33mcommit 31fbdb96e07dac603689a240d880bba89b029641[m
Merge: 42603ce3 055d6097
Author: terrafrost <terrafrost@php.net>
Date:   Tue Jan 15 23:48:54 2019 -0600

    Merge branch '1.0' into 2.0

[33mcommit 055d6097af6fb3359e2f7ef8a804d02b785eca33[m
Author: terrafrost <terrafrost@php.net>
Date:   Tue Jan 15 23:41:49 2019 -0600

    SSH2: more strictly adhere to RFC8332 for rsa-sha2-256/512

[33mcommit 44a56b8a1f3c8c6d177a347bd8a31cecfbec887f[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Jan 7 08:06:10 2019 -0600

    BinaryField: fix issue with negate

[33mcommit c53ca28b25885adeeeba050ce0eb89465c01f2a6[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Jan 7 06:42:00 2019 -0600

    BinaryField: CS adjustment

[33mcommit de631981975b13f1918d41b54cb6507a1b13e51f[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Jan 7 06:34:00 2019 -0600

    PrimeField: docblock cleanup

[33mcommit 4ae33f9bde4a02e034a59da11f5322ce14e7fb00[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Jan 7 06:33:11 2019 -0600

    BinaryField: speed up multiplication for GCM and smaller curves

[33mcommit 835b1207fa45c6c9a7542a0fd5848a318815f8d5[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Dec 31 14:14:43 2018 -0600

    SSH2: replace "$this->object !== false" with "$this->object"

[33mcommit 17e6938fba7f9e3bce9ab45398cb630b1014f607[m
Author: terrafrost <terrafrost@php.net>
Date:   Mon Dec 31 09:06:12 2018 -0600

    updates to Exceptions

[33mcommit c6f98076332369cdd47d993d4daaf527ba578964[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Dec 30 10:14:51 2018 -0600

    SymmetricKey: don't define self::$gcmField unless we're in GCM mode

[33mcommit f98e0afc76cc46e9a649285299d9e0228d1c3371[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Dec 30 01:55:56 2018 -0600

    AES: move GCM code to Rijndael

[33mcommit 5abb16dc6d52701da336927f5b110375d9b647fb[m
Author: terrafrost <terrafrost@php.net>
Date:   Sun Dec 30 01:04:18 2018 -0600

    SymmetricKey: simplify mode setup

[33mcommit a8d07e3dcb4678ab9261cc16bf030b63e4b7346b[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Dec 29 23:21:18 2018 -0600

    SymmetricKey: make $cipher_name_openssl_ecb static

[33mcommit 49be6e5529ca4c19a4bda8e5236c5431f4c3780e[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Dec 29 23:09:33 2018 -0600

    Hash: rm function_exists calls for hash extension functions

[33mcommit e2256f42673633e0e5ff1335faf3a3aa059a894f[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Dec 29 23:05:20 2018 -0600

    Hash: fix grammer error

[33mcommit 97d41fd3aae2196dd576286c9b968355a312172f[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Dec 29 20:54:18 2018 -0600

    SSH2: make bad_algorithm_candidate method static

[33mcommit 5126937d40df80a57dd78a9978b6bc2d0330741d[m
Author: terrafrost <terrafrost@php.net>
Date:   Sat Dec 29 19:35:05 2018 -0600

    Rijndael: replace block size switch with a single variadic function

[33mcommit cef647f9a944be9d461916608e880391d642ebf7[m
Merge: a30cfff7 01c92a59
Author: terrafrost <terrafrost@gmail.com>
Date:   Sat Dec 29 19:33:58 2018 -0600

    Merge pull request #1330 from terrafrost/gcm
    
    add support for Galois/Counter Mode (GCM)

[33mcommit 01c92a59f83c4263fe3adc977e6c31484f8edcf3[m[33m ([m[1;31morigin/gcm[m[33m)[m
Author: terrafrost <terrafrost@php.net>
Date:   Thu Dec 27 08:31:35 2018 -0600

    add support for Galois/Counter Mode (GCM)

[33mcommit a30cfff79ca530384698b3bf324b7c3108f93d57[m
Merge: 3dbc50c6 d37969a3
Author: terrafrost <terrafrost@php.net>
Date:   Sun Dec 16 19:04:43 2018 -0600

    Merge branch 'master' of https://github.com/phpseclib/phpseclib

[33mcommit 3dbc50c6673a3ed2f9910b997d93e552fb2eeb28[m
Merge: b76a67df 7fb7e6ce
Author: terrafrost <terrafrost@php.net>
Date:   Sun Dec 16 19:03:44 2018 -0600

    Merge branch 'post-ecdsa'

[33mcommit d37969a34555e6be60b911779e41bc1e5bce1b2a[m
Merge: b76a67df 8e977b4e
Author: terrafrost <terrafrost@gmail.com>
Date:   Sun Dec 16 17:46:28 2018 -0600

    Merge pull request #1322 from terrafrost/ecdsa
    
    add ECDSA / EdDSA support
