# Streamwide Test Vectors (v5)
## MIKEYSAKKE-UID
### Test 1
Generating MikeySakkeUID with the following parameters
uri:                      sip:user@example.org
kms_uri:                  kms.example.org
key_period:               2592000
key_period_offset:        0
current_key_period_no :   1
generated uid 74e2af803ab5d72841bbced0ce319ffe64f6fe23c88a2d258aabcf6ac5658ef4

### Test 2
Generating MikeySakkeUID with the following parameters
uri:                      sip:user@example.org
kms_uri:                  kms.example.org
key_period:               10
key_period_offset:        0
current_key_period_no :   10
generated uid 94fb1a697c15d7e9d6b7062066affebda2d9e346e0090d67525c0c3ce666eafa

### Test 3
Generating MikeySakkeUID with the following parameters
uri:                      sip:user@example.org
kms_uri:                  kms.example.org
key_period:               25920000
key_period_offset:        100
current_key_period_no :   1
generated uid 3c0ad8828cfae1ad1d08b27cc7b61258c6cfcd405081b68cd778f1e1c7f562a7

### Test 4
Generating MikeySakkeUID with the following parameters
uri:                      sip:user@example.org
kms_uri:                  kms.example.org
key_period:               25920000
key_period_offset:        100
current_key_period_no :   2048
generated uid c88b3fa5e36a08985d10f7b31a631b0265e8249f0312435e4984dbc3765c7f0c

### Test 5
Generating MikeySakkeUID with the following parameters
uri:                      sip:user@example.org
kms_uri:                  kms.example.org
key_period:               25920000
key_period_offset:        45920000
current_key_period_no :   20393844
generated uid 8dc05540167345538475101514f4eabd384abd6ba665782abb312ecaf05934e1

## MIKEYSAKKE-PAYLOAD
### Input
* KMS Init
    * KmsUri        : kms.mydev.streamwide.com
    * UserIdFormat  : 2
    * UserKeyPeriod : 16777215
    * UserKeyOffset : 0
    * PubEncKey     : 046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6
    * PubAuthKey    : 0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f
* KMS KeyProv for GMS
    * UserUri           : gms@streamwide.com
    * UserID            : 15a4d5b12856538d02d91fedbb766e6dd377b014c92e216666c8fb678608d20e
    * KeyPeriodNo       : 236
    * UserDecryptKey    : 043f591611206a0913ecb68ab28e086ac1148fbd5ce4a40bf00a186653ecf6f0055f4f1b5ef8a4b527d33dd28c731c7b2829d6329283533d499b04c31e2d30437919f486ef76c8a6cbca2f279724539e52b3a1760077670fc35756a9417625d57876717811bd3f1fb8fb473b547ba874a8f5d747cd63b2ebcdb150f5b454a46ec2512a86f0672439d3121a0eddf5995f18e1c77e3423ea34427b62281977e3afb9b5c8766c5a32e1f9b29f0bb12d46a03f8f3ec7357e59f969473bcf4d4cdc3cdedb6e7982e6477117a3c02d86165896485323c96f53a330e5e995ce83b23127542f2177916d5007a5aa116680093911d4bc587cd94e2bdec36d7290ed4f2d3998
    * UserSigningKeySSK : 2e7237faa18a874b88d955199dea974b7d0fefcbbae1946baf659b26a4d05a5e
    * UserPubTokenPVT   : 0468a24d49b184d7008d22f63a415debd38bfa9295f066fa6ada5951c2322d2eca1d6f1d994f22710daef776d9c54d9a338f32395080d6f2bdffb6c7895f12cda2
* KMS KeyProv for Alice
    * UserUri           : sip:alice@streamwide.com
    * UserID            : b5c452309219da6a3d805615548d6c1b0f4de45a6b48fb13d9a24d857fc03dc4
    * KeyPeriodNo       : 236
    * UserDecryptKey    : 0428b44cd6dffd2e7fe73521a5c514738287df177c1ae841ba6f5d72601b9c6bc5509c3fd800ac1fee833dd81c74ab39d2740a10fba25cd9b0debb25a3da958cf52e35e863d2db37ea22b318d23d9911d36f585eb110e430123f3cd84d2692a4013bc7f59533e5da2083d8e6e8b96764eb8e8be599dc2361e7428460b8490200417baa5bac10efaa5262301b3110f6da9e8bc9c4b62827c3d4f4070a8e341346a326a23f219d2a99298036615956bb85a60cf303d15d469c1ee837c29cba5dccb28d74e4ba0d83dac9400d72eecb1817cc60127203f1321e82b7a24f60c07f1804a9895cbb455a94694a5ef627b1c631760295dad53f0eed1714ba52d5a932bddd
    * UserSigningKeySSK : a1be54a56c7905c06abd2be177fc0c137a32278c9067550b0f0d93fb630d2428
    * UserPubTokenPVT   : 0426cd8b0a33af9b381ee53ebc6841aed5c1c98fb0d2beb9c7ff98d7c79808d1f566659f6b735016192dd9984df56e54f3f95c76ac4638c1f3d3228f3c752c8cc8
* KMS KeyProv for IWF
    * UserUri           : sip:iwf_legacy_v1.1.x_format@streamwide.com
    * UserID            : edb3cd733168a81106e366c2ddc0e4bc323e9069d48edfe2b3b0f7033bae962a
    * KeyPeriodNo       : 236
    * UserDecryptKey    : 0424b74f88f8fb0cc7b1fa8b48ef1cd676ac776a3dc98d41c7e334308a7068906d44eb13ea49c472b8835685a4151a2705fb78e0371ff351d7ed38de0977ca10ad23c91a569010718f0498daa45f46d8c57e40d96081b839d59c0a1ce06a5044f53ec9b379e730da0605cafcb922b018023c463478d63298bad759dbcae40e8120703f7badd9e5635a22e2a95d7fa94455225065d1d417b3eba279a77882d50425336ed8c5529c608e1777dbad5da9cb23d2fdc5ff0225b1c2237463ac107d9a9f3160e2e4b0e6601fa7609fe28640d8b03cdda21411370a5610758436ab98793caef1391ff7eaa01ee15e4893d72c648eba206d17199cf416e56e09e7bca3ae3d
    * UserSigningKeySSK : ed3162edf45f6e6f0f0939a02c84795c2ab78f714c91fe0254ca0f48eacf6a20
    * UserPubTokenPVT   : 0411d4c57e7b945588148a55f9e88bd1d62017f4fab600af6bf4dcdb05e6f75e9441e20f7a9e2371ebb34692b941270b52744d1699538b41a4cdf043101e23449d
* KMS KeyProv for Bob
    * UserUri           : sip:bob@streamwide.com
    * UserID            : 780851cda91a9c33f941cd3a2831697e2893264754e363f8a0cef827eb201a81
    * KeyPeriodNo       : 236
    * UserDecryptKey    : 04421d385f108bd51f66abbce40b899efe187dbb08085d9a535fca8766677db317812e48da407235d73399d4d2e2ed4f5a35d7694b64595ce0599e4d3592f5b57ede83890fd798aec2cd96f333d6139d9f7ecfecbb79b769f5fbbc6825beeb25999acdf6fb2edd369176f45db0caf5909aa81512e57064c46ae1c23df9284ffba55741cde0b7a8145fdbea76b4ee243d79bd70db4300c55570f342ca0df98e8f3b410e1df4ccbdd279403d3da06cad4c5db8d4e078a191a7a0545391e8ca72e51c793448c4ba8be71fbac90a84ded3d6127c4d7438a3132f354b283d65da75a5070ecd96f02d694c505efcb05caf2290bf15ee45c15a0e652496b88acbaf1d26a3
    * UserSigningKeySSK : a36885736f21b6ceba48448093086f4ada1ce099bd77e3047c04529ac3f4d4eb
    * UserPubTokenPVT   : 049c203fda536ae9481eb7f3a1e4662d0adaa6a3b7d3fff0c2dfadd148a754af424d434253b62dcd08eb6aedb6cd091e09f8539d41d3ef2d0ce07e8ead352f2dd9

### Test 1: GMK
    * GMK           : 07d1a1677ac36d8e81620484689b3c2d
    * GMK-ID        : 0df9bc39
    * GMK-RAND      : ca2f5d51ff0866362c1d85a56f84651e
    * GUK-ID        : 06a12aea
    * Initiator URI : gms@streamwide.com
    * Responder URI : sip:alice@streamwide.com
    * I-MESSAGE     : mikey ARoFAQahKuoBAgQAAQAAAAgN+bw5BqEq6gsA7ImNqAAAAAAOEMovXVH/CGY2LB2FpW+EZR4OCAEAIBWk1bEoVlONAtkf7bt2bm3Td7AUyS4hZmbI+2eGCNIODgkBACC1xFIwkhnaaj2AVhVUjWwbD03kWmtI+xPZok2Ff8A9xA4GAQAYa21zLm15ZGV2LnN0cmVhbXdpZGUuY29tCgcBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBC3aUP1jhkJ9H82+MG+m8UQpuYzjR5JCHxwWvskS8Mny2EqaxY3EcWJhrcq6qkW8/JHV13Ajl7ONGzddlw0JgInw5TgkvS8nxlQFtZTNDAQNYfgHfB6mt2ngI7pK7TBSWLx6kWJtP9+GOsQBq8XF5sn8lU1oc5QYueVprQxfbvCAeNptCSm0d/8tTS1MRoZinm1ptcc56tfqR7SDGaEf4qIwgi+z6OlimTqd4TfQakk+0SS1N6+FpyTVJaV+vHH+XhbdNEAqvEF4kkVa9uBVbz3oibD6qE5r1p5RPLhMdbFSt43kD3m2W0bywQRLcd83h3ToKJjUVZmiJ1looeUhlmLDlOMS1o5aCogO1Y9BzxcIBAcAR0MAAAAAAQAAAAAAAShwT6Qcj+IPiBwbqw0y2MoGoSrqAAAkTt3Dv4wqSl0/yYSEQBI+fQVNq0MI1QV1kgbMeJ0FpM4OSTZNIIEiJZ8Dj82CPpmzeAtvAA00Ld0hK6wK+/O6TLeVfE6HxgAGWUHFH/27VKKiyKPa0tpfDhlEEnWzJiVzWOD/yzXdBGiiTUmxhNcAjSL2OkFd69OL+pKV8Gb6atpZUcIyLS7KHW8dmU8icQ2u93bZxU2aM48yOVCA1vK9/7bHiV8SzaI=

### Test 2: CSK
    * CSK           : e06e65106183547342d3e8a6ce2540a8
    * CSK-ID        : 2ddd5bf0
    * CSK-RAND      : 4d13c41798b82de13b701a9697328edd
    * Initiator URI : sip:alice@streamwide.com
    * Responder URI : gms@streamwide.com
    * I-MESSAGE     : mikey ARoFAS3dW/ABAgYAAQAAAAQt3VvwCwDsiY2oAAAAAA4QTRPEF5i4LeE7cBqWlzKO3Q4IAQAgtcRSMJIZ2mo9gFYVVI1sGw9N5FprSPsT2aJNhX/APcQOCQEAIBWk1bEoVlONAtkf7bt2bm3Td7AUyS4hZmbI+2eGCNIODgYBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20KBwEAGGttcy5teWRldi5zdHJlYW13aWRlLmNvbRoAAAAbAAEGAQEQAgEEBAEMBQEABgEAEgEEEwEAFAEQFQECAREEfQkdJ4BYO/O2WHY5cZ8HZMAMm5n9MLxgvJCOAv+759hNMLBMPPvnEjivXxmb661AVDQ1haLXdN52IbHmBgLJTYeyPQX8CVon6WVshkoTQCMWMRND0jdyGFRlw24VGkYfL2Z+JBvta/dAy4+GZYxTsqXzF7KOqH4f2P/aY5eVHAEvwF2zwUXUB0nOIs8Jtq/7dT+hwB5/mvoQiK+uiFkdwEvltVw6ZCzpWiqO+ly/ulyhYXubtqqFOvKMWLe/dqdaEsOMmsP4ZFTsYYOCU5B9IbrQ02IZDNJlNasQNe/m5MrC5+WcZkTw54G/ViwtQlxhuoi/E8J6XL0bY4n44uXDvmRNXMkLCsMC1y/iJVKWo9EEBwBEQwAAAAABAAAAAAABb37iYqxNp/XQanLehoFqvi3dW/AAACG8cPNwhkxPqPeos5kqzBfSM1U4vqkNYBaZK2uYKuhgCPAggdf8YqSPHsId0HAlWI2c3FevHT8Yd84XlCTMbp/Y8UE/qNnqyYDSyrpmrkj9okfl3jPsNoqzh8uddNZSTDzr5UAEJs2LCjOvmzge5T68aEGu1cHJj7DSvrnH/5jXx5gI0fVmZZ9rc1AWGS3ZmE31blTz+Vx2rEY4wfPTIo88dSyMyA==

### Test 3: PCK
    * PCK           : b4c96b703acd5c1bf7d4cc45068d9965
    * PCK-ID        : 16992638
    * PCK-RAND      : 02a28bddaf984c5e0563bc1ce857df83
    * Initiator URI : sip:alice@streamwide.com
    * Responder URI : sip:bob@streamwide.com
    * I-MESSAGE     : mikey ARoFARaZJjgAAQsA7ImNqAAAAAAOEAKii92vmExeBWO8HOhX34MOCAEAILXEUjCSGdpqPYBWFVSNbBsPTeRaa0j7E9miTYV/wD3EDgkBACB4CFHNqRqcM/lBzTooMWl+KJMmR1TjY/igzvgn6yAagQ4GAQAYa21zLm15ZGV2LnN0cmVhbXdpZGUuY29tCgcBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBF0yVtvyB49KhE+ao3Hj8W+gNROh57Tk5/9BWa2jNv1YLxYpBxV7206wlv/WHWlzz+NgptVcWgECwaekKAGURuP4TA+dRQpkGvqW8wImX2EF8Zjy+a1pOZMZ3YFAYRiYEAAGmOByWKdDDOT0TfgL2pPFXS1CvZ/bZtQL03Q8fL/JInBbnv4dSYiJ9/fkeeqg37yIRsjA3Xfds7k/2o4f0s4NisOs74F2xjE12l3/764H+g1y2rAMAWkjaJbS9jbVfZNGDauoRhq8zuXEXH1c5ftqs4VEPeOPmWjAkW1rQe8KxkZbmtrygtNpBIXVeZZEyorzD+MyQ2zL9xoGVs8cToze4NOxYt19SOInSpGO5Q0vBAcAREMAAAAAAQAAAAAAAfb0FW9YVClhy8qPsQ5m8WcWmSY4AAAhpTVAAi78zLNoUFiVPGjByx4N9U9gccPiQl1eiCiFLm8BIIFAPW9oE9lYM5oS5nQS9bWbJzGv+vWNAh2uUWmyG/OTGMeFzAD0JFMB6zcf7ck7GFns2OEPIGGx+7046le+CihyBCbNiwozr5s4HuU+vGhBrtXByY+w0r65x/+Y18eYCNH1ZmWfa3NQFhkt2ZhN9W5U8/lcdqxGOMHz0yKPPHUsjMg=

### Test 4: GMK (legacy format for IWF)
    * GMK           : 07d1a1677ac36d8e81620484689b3c2d
    * GMK-ID        : 0df9bc39
    * GMK-RAND      : cdd4e71ad92cc090f3a13cb66a2ecb18
    * Initiator URI : gms@streamwide.com
    * Responder URI : sip:iwf_legacy_v1.1.x_format@streamwide.com
    * I-MESSAGE     : mikey ARoFAQSCCacCAADK/rq+AAAAAAAAAAAAAAAAAAsA7ImNqAAAAAAOEM3U5xrZLMCQ86E8tmouyxgOCAEAIBWk1bEoVlONAtkf7bt2bm3Td7AUyS4hZmbI+2eGCNIODgkBACDts81zMWioEQbjZsLdwOS8Mj6QadSO3+KzsPcDO66WKg4GAQAYa21zLm15ZGV2LnN0cmVhbXdpZGUuY29tCgcBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBF6WXZDP1xXQb6fqRvMIIWmyvxj3mWH7CM+1KiNnW67b1ZyKQfnNTTVd6qOmDw5gOl2AJsvvVT2hRmzZENyjyVRp0njGf1jT7kNElNm604PwuYPUrRZfEJkx8S+RlZ4Yzi3e5rQiT51qw2fs6B9Eeikz8G0ERl2OL9hK9Fuhei4VePlS0iDpxuDnUmHik4nTc8F+7ApxagH0YP/6V3EgnLMoBnjW6qBK2F+2BTXNY8uZ3FBmk71ta8O2vg32fhQZpRqv5XE9tMkG0Xdkrk2IwX234rVLlgGudn7kNuQUS2zbsh6FdUYXCEY8zzMIZMCAbEjHkm1CIMlJ+Qj2sTkW8YO4HjdsRwl5Ja6hNciqF54XBAcAEQEAAAABAAAAAAAAAAAAAAAAIIH/fqEkt5+oaoFcfKQ58KNfBa9wOmqCE6kGkoPOHu3amjBGJiTGbSZLzi5SElAtgAIY1zsJxcUoLV+65v9s8THsBGiiTUmxhNcAjSL2OkFd69OL+pKV8Gb6atpZUcIyLS7KHW8dmU8icQ2u93bZxU2aM48yOVCA1vK9/7bHiV8SzaI=
