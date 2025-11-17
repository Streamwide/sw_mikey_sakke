# Streamwide Test Vectors (v4)
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
* KMS KeyProv for Bob
    * UserUri           : sip:bob@streamwide.com
    * UserID            : 780851cda91a9c33f941cd3a2831697e2893264754e363f8a0cef827eb201a81
    * KeyPeriodNo       : 236
    * UserDecryptKey    : 04421d385f108bd51f66abbce40b899efe187dbb08085d9a535fca8766677db317812e48da407235d73399d4d2e2ed4f5a35d7694b64595ce0599e4d3592f5b57ede83890fd798aec2cd96f333d6139d9f7ecfecbb79b769f5fbbc6825beeb25999acdf6fb2edd369176f45db0caf5909aa81512e57064c46ae1c23df9284ffba55741cde0b7a8145fdbea76b4ee243d79bd70db4300c55570f342ca0df98e8f3b410e1df4ccbdd279403d3da06cad4c5db8d4e078a191a7a0545391e8ca72e51c793448c4ba8be71fbac90a84ded3d6127c4d7438a3132f354b283d65da75a5070ecd96f02d694c505efcb05caf2290bf15ee45c15a0e652496b88acbaf1d26a3
    * UserSigningKeySSK : a36885736f21b6ceba48448093086f4ada1ce099bd77e3047c04529ac3f4d4eb
    * UserPubTokenPVT   : 049c203fda536ae9481eb7f3a1e4662d0adaa6a3b7d3fff0c2dfadd148a754af424d434253b62dcd08eb6aedb6cd091e09f8539d41d3ef2d0ce07e8ead352f2dd9

### Test 1: GMK
    * GMK           : ead9e20459a5cbe881607f643a6f5ca5
    * GMK-ID        : 0e144748
    * GMK-RAND      : d154c2d389bd9ec536a90e863b3474df
    * GUK-ID        : 034db662
    * Initiator URI : gms@streamwide.com
    * Responder URI : sip:alice@streamwide.com
    * I-MESSAGE     : mikey ARoFAQNNtmIBAgQAAQAAAAgOFEdIA022YgsA7IZoTwAAAAAOENFUwtOJvZ7FNqkOhjs0dN8OCAEAIBWk1bEoVlONAtkf7bt2bm3Td7AUyS4hZmbI+2eGCNIODgkBACC1xFIwkhnaaj2AVhVUjWwbD03kWmtI+xPZok2Ff8A9xA4GAQAYa21zLm15ZGV2LnN0cmVhbXdpZGUuY29tCgcBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBCkcziv5PVX7PVMDI1Y/b3n2A5qul6eXaeK2HEKrCf5KFgfGOWF+y33g8TdBD3IsbV4Ey7HJiDKkgDZa8QIAVAh3+VWP30ykJ8BmYxZM0+BuuGrETWTO9y4pohYBMHPIL3cnlNulxryRWgU95ErGg7wuCKwzRJeC6UciStR1iN1UCkNo7IvRZznjtB9O/oAIPP7sshOxsTcXhb/nI5OiAYwL0F2B7lymm7AzgHTynWKSTYyKoo+wQxb53Chnb+/XlkJNFtayZ1CSa5Y8nS4QjUEyWAopFwBSQBxF50nHOaEXLIJotETja3OYt9Z0y15vNuVY3TY6csajVt8IxdWL4f80A/pBjnAQT7yCkmo54YFtBAcAR0MAAAAAAQAAAAAAARBSxhhwr95y11DPkNnVfZEDTbZiAAAkKvD+khpd0bDkhhJdbogNWVQIbAe67Q/OFifVP58MjwrixjWRIIEwpGB+08FszdvSNwTRbZ6H0z/puSA6LVP2MJo+jFLOAAOvjK0Mg3koTcipQq8qQFhffl9IIn/NuKjcxl0CxMulBGiiTUmxhNcAjSL2OkFd69OL+pKV8Gb6atpZUcIyLS7KHW8dmU8icQ2u93bZxU2aM48yOVCA1vK9/7bHiV8SzaI=

### Test 2: CSK
    * CSK           : 332b34a97360588d05cdabe1c84457d7
    * CSK-ID        : 2fe0b176
    * CSK-RAND      : 2d8772344b7ed2ea70d35628406db485
    * Initiator URI : sip:alice@streamwide.com
    * Responder URI : gms@streamwide.com
    * I-MESSAGE     : mikey ARoFAS/gsXYBAgYAAQAAAAQv4LF2CwDshmhPAAAAAA4QLYdyNEt+0upw01YoQG20hQ4IAQAgtcRSMJIZ2mo9gFYVVI1sGw9N5FprSPsT2aJNhX/APcQOCQEAIBWk1bEoVlONAtkf7bt2bm3Td7AUyS4hZmbI+2eGCNIODgYBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20KBwEAGGttcy5teWRldi5zdHJlYW13aWRlLmNvbRoAAAAbAAEGAQEQAgEEBAEMBQEABgEAEgEEEwEAFAEQFQECAREEg2yJfJc1Hxuo6oCPXSlzgLpaTf+GzdN4R6vNba9pY15ipGP3ECbJQYSOQ/Hd5aXWW/00WRoAWag2oeto2NktA81b91nkczEbz0kZw0OdQXchpxfmjenmiNCrK5Sk72Hd7MI7d21S9af0Hbbxjt8yqaPMdl8ugfA7PiDJxlVUUM48wG7ZpMu0iYL23aDI7EoEx126RR9k6MsD7DDE90mUxUopZJHrEmM9641tZFuQuhw8hipeppkSg/v62K/afHz9/C+HlCJHBv1Pf/6+D5U7sdVogs0qWUMdspH79YTW787hsDuvTGstX7vkovZsx45dtCRjZSTvcsIRGQ1kodNOj6wUGrYbpLjB9uzUO/ER7E4EBwBEQwAAAAABAAAAAAABfnLxfi4vVcUyYDm4eyFwyS/gsXYAACGQ0BK0lmoQaEpj10IZuO/yVDFc2oNuuFumXaImtbORin8ggfXn3aSYuh/tdmqF7bHeofrM4sJ18wJaVxG6W2haF62HxUFRXFEvRVZN06CsdypONBVdzLxISCTn5mlAn+9zV+gEJs2LCjOvmzge5T68aEGu1cHJj7DSvrnH/5jXx5gI0fVmZZ9rc1AWGS3ZmE31blTz+Vx2rEY4wfPTIo88dSyMyA==

### Test 3: PCK
    * PCK           : 3f6786f2bb68852d053fa317ca1d80c4
    * PCK-ID        : 1278dcab
    * PCK-RAND      : 42b4ca1be2041f6f186e88d203de5c7d
    * Initiator URI : sip:alice@streamwide.com
    * Responder URI : sip:bob@streamwide.com
    * I-MESSAGE     : mikey ARoFARJ43KsAAQsA7IZoTwAAAAAOEEK0yhviBB9vGG6I0gPeXH0OCAEAILXEUjCSGdpqPYBWFVSNbBsPTeRaa0j7E9miTYV/wD3EDgkBACB4CFHNqRqcM/lBzTooMWl+KJMmR1TjY/igzvgn6yAagQ4GAQAYa21zLm15ZGV2LnN0cmVhbXdpZGUuY29tCgcBABhrbXMubXlkZXYuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBDFLUzkJZ3U0JnILRLhUxIjQ9+4MH6pt+0jFQ5mVofUGkrh+I+jchQbElBQfzo3frdDERJPDdu+DvgMr4WPZLaRsQQrrDQwn3b0OjOH1k1rJoFwzT6cbiSLdAvsS35p+o5j1b2+zRx1qcr0yAv+7r0GWWuc8jCNVFG2ba7crszqWHYpw6bGxsLb9UAi472VqnaOaaWKqjQVi3d8MJ4O/vwrs1KOR4TlGm4IvE7Hm0Lq/kihn7Z2tecpwH8q2tRKruDTguejWWXxbpzL9sC0Gy//QVWyOubMcm2uIBeeLFMH2teINtXaIRbjA02fUCrsFJOLeF24Cwn8xeVp4Pkx3wtTo1Hagldkij7cKUHSSIjoDBAcAREMAAAAAAQAAAAAAAWrU4lMsvo95rzkbhSBt0i4SeNyrAAAhDbbGHXzIxoVTMy6APh+1VwiBCUGdgjCuiodUctxha+N9IIHu/3AmVRF1gajKf5kt5zktSGqG8K79EH9mu5xLYV4YKDTOCKKNkklz01txusQR9emtNyjNLPykeaeKX8WE4mDzBCbNiwozr5s4HuU+vGhBrtXByY+w0r65x/+Y18eYCNH1ZmWfa3NQFhkt2ZhN9W5U8/lcdqxGOMHz0yKPPHUsjMg=

