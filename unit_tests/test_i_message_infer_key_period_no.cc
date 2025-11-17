#include "keymaterials.h"
#include "libmutil/Logger.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <cinttypes>
#include <libmikey/Mikey.h>
#include <sstream>
#include <util/octet-string.h>
#ifdef HTTP_REQUEST_BY_CALLBACK
#include "curl_requests.h"
#endif

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

typedef struct key_material_values {
    const char* user_uri;
    const char* kms_uri;
    uint32_t    key_period;
    uint32_t    offset;
    uint32_t    key_period_no;
    const char* z;
    const char* kpak;
    const char* rsk;
    const char* ssk;
    const char* pvt;
}               key_material_values_t;

key_material_values_t table_key_material[] {
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 1518,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "0464451e93374987094bc807157b640c0d4229fe18d0c8f3bb7de27a993483a4148752fd4275ce6ba206c64fe3351c0db9b280f1c0f61e48fed35027d20200f429ecdd5ded7c61c529cd221deddc996288ed7e69e13eadfe422a9dcc83ca0d901740304fc9e1f2ea170d52065d81848dec0200e5bce28c20aa7994090f130d320c4d65468827c02ea22cf6fdd764109e1c72b12609392eb31b1690f07f8722feca4edc492e8c3c49c4b4a5700228b006c6cbfb376fc0905d3694f98a51aad1c0e27bcc9c8b1950e990762275d9a5d7399f179dfcf4f923cc96163838bdd73203eb5fef3fba7623a45916a68ad0db5999d305b3326ce54b31df42f861c1746c02ed",
        ssk             : "df56148987d2b3f260bdad8c5e0ca6750bd38a6f0b0e3a34f0f4655af553753f",
        pvt             : "04138021ccfb455defcacd02b8807af5db87b37e49b3a111f125a1cd496d5f2895558cc6b834b0f1fb90afa50e61e3e571cad35f0950aab39bd6a55258af66d56c",
    },
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 1540,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "0421c4866673edd538b6ba4ce10e342d9c5af61febb6bf45e4e4dafa48a70ed7952ba14fb2499a4ae983e18471669d49beb896998c8b55011ad44b02e8139ca780ff8f99503e3252b6da2aa47710ea225e7832645723d4223e76e38039d4b3821b6eb6776b529a9f780b448fe0db3d0c046d510e861eaa0dfd27678b8ce0a283ba3c9814cb4063180dc30ebe1d107ed2e5b22a3dac966c75c2c3152527fc4b75f341f7cd7660f160c19eb866cb8ddd628c51d84e3a5074f6eca800b0cb2fd75278eff2c6433a4df7e8f9de3fe38cf9e93f65f81b59312d7aaefd060ca548856d6163f6406936d5702f0e016e152bdb8bd8cbe6f0560fd738e896804a2e5a7745c8",
        ssk             : "d5879891784638d4db6f487f5ff9f0bf5627b8d81a6be707f59cecafb9475250",
        pvt             : "04be58e660c43dca8cbe29c6d8f6469ce0d0f82e901b91d1838044b133d6ae28b0770e7482583aa5eed512e7f1e4e30926c65b0754b2dd64e2f263fd70379ac570",
    },
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 1531,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "047527005998a0793ff64aefd89d052aad5802b74e61fcc84872c4b5933fe82afd4b2bd1b235cd3dc030a3ea103334c4e545966d4e551132482aa2c4eca83b919e3bc3b8c905a07f676c55a6720cd6a2443f6d85f8b1acb50128e198011f9e288e38b23526954358b1b307043eb25ce94ecc48e627fcb29046e460856cbec336c753092f70a16192b474b31d80cd154674ad1141ba54ca02a9e4bffb16a9e216ad1d8b0a6cf9edf28fb6ac898ae5ed936c793c0d3cc4d71a045fb7c3a0668191f4d26ad1d5b5db0bdcecd4cde75f806800ec6b715dcf121e6f7ed8a47ba9bf8b79452384f1f5869e011532ef31965772f91fe2b36ef03885bbee8642c561b8a976",
        ssk             : "fe475eb3bab5324d18e8e540d8ce325937f4452e3764809f944813a16b536b53",
        pvt             : "040976aea39dbc3b7a0fbc1fb35f3c3aed6410fbb5107aa1e8c54614eaf4ff32ac4b71fe8d70089a5cd938afdaf719daf92fd11c8af414c46a0584b8bcd6c21a55",
    },
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 13,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "046d5dffb9ed2a26e363b27966a2a8503cbc865056084e1785116e07723f3a82e6ca9eacf761455fd8ce9ba0a803f6598a4ac4c09f003e68641cdc6e84577a6778ca33d23f330965e239c76f9364448f47a1a72c3f22b94c1580edb80cff153e33235b91fec553707f4190f47173ce6549a8ef9010295e5693bc7f43b47144db47423cefb38bf165d257a05b807971826a2d7320edf877c4ce287c2f4a3de8385456e845e315e2b19b699f88d083f59713e10c2becf639fda5cd0210dd19d1a2b21364ff1748627d185eb6e5e02928abbdaf52e2b49fa3c46a852d1976ce155d79ed2eb16381db17d3a13e3b4e2b8f7f62d3c00b8c863a2be495a13fe54f2f869d",
        ssk             : "c9a9a7314072fd57f4d4fee7be136f54ef0deb454944537ed7a7ae36fe32f64c",
        pvt             : "04be1dc617f94021de40ae9d432d4e272129ac09c7ebb7dd67b93bb324ce498049dfb14e6949ba0a46431b851b0933e6511bb83b9021b49ac693fd47c01c75b705",
    },
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 15,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "042917bf91752e26dbb49534b72051b0ca2276082614ad0805464ad3f84220ca8f7764fafdb2556d4cd9b5e4085e532a954092fc456ff033a82d1832117623d079f42d4a0867bdc58cda5ebbabc1bb3a89f993c217104068a13f1e008fb822a11d301c1ea623b34e3f1dfa626279a489dd44017418315b3214aa5526ff4f1f0fbf85ea6dec55ed809fc5be74cb09c5a861b5eac0e26949d50fcf13831db184d90d6a3a225935677b97313fdd83812d205eb9b04882a23fcb691cae852043db5bec8724be90320ba86c0365f13b8660aece084730108ab1048f77026242e09515f9ccaf96a2359644b28d5a6d550ae3e57ad90abc8cef22f5087466eae2ac3d94f9",
        ssk             : "daa0262704f88f7a5fb84169fe8825a9077057c340ca39aeeaba639224b63d31",
        pvt             : "04e9c75f0ef0d43a0c2ef1197e009292017ef5b4752e93216a4bafac027c447eee348cca5270e0a4c223a003ef5cf9e413f403974cd78bd3858363e9cbdf43bdbb",
    },
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 1655,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "049820ba8554f664df030533103fecd7b84b80a65948221d18eb4f9ebd76a5c17836ecbbf8b1062afad5af74519392cac27e8a465c8b0c1d9de055daf925b4b813532ed12cb3fd97e7bb97a2140d14fbd1b7e2e7eafce0de84d6a1262e2d3b36856fba83ed3fd9e1250409bcf6db6011f1379ee9803bd291a5e68278658ff651d1321cdc5d5aae349e1500ebf2832c979c91099011a59f2afcb4e35c5e73bad406c0d53e3a6d9b9a4685623b0488e86b5f9a1e6cfe1a63a4461c308fb3fadf0a00bc656ddc3df4f287252da99e28ca08e91aab60d651ed00c6d2e49c0188b2dc0b69362f6fcda08cfae5d86cbe9b5209069723b67378c840de2f7e49781691df84",
        ssk             : "44d9c8f331849eb984d9ae2f5b79989e30dbb3877ec85bfdea4cd16de1f78773",
        pvt             : "0426e83b06ea817e708d2a3e6748d27173495dcf7d1c935d83f0458dcac22c918459c7beae1c7433ab28c1452797024c22944a45bdb0cae176d8ca433627a9383f",
    },
    {
        user_uri        : "alice@org.com",
        kms_uri         : "kms.dev43.streamwide.com",
        key_period      : 2592000,
        offset          : 0,
        key_period_no   : 1657,
        z               : "046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6",
        kpak            : "0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f",
        rsk             : "048d551c7197418b1b4ac132f0004e9bdf19ab424c02076c7191aa99fe99292c08d7cd1b63d134dfe2af4c22539b27706cae5246abd0d8e55feb21fccff8fb2453505fb8ae40eed57a4ae42f91af53e5ae176151594dd926774897d06a2b40a775d741121dbdd20aaef30e670f55f16b12e46194243b04faded5003e8b1b4669525d858dcb82d7416ecca3ec70a5c0bf6c96c4b74d50d919e588b2912eed1051205aafc37f1bb8cdb20aa891e0c2e7c4f78ce112d73d640db5125a5b8918b3344cecf7741002e3fc8395e1a865a0090dbbfeba738c233f4953d606d5aef3099b15e683cd0d1318f1a61e4254bca6d924d5b9eb7ea5e2b804a51e4a03bb8468de7f",
        ssk             : "7673a40df0a7e31f6a2b07189370a6152378c9ef206c615a7aa181b7451b2503",
        pvt             : "0449bf72cbb8de36e1baa539869952082eb6f7b1f8f31add3c37c10a3d5c012851f78b51730b71c78b56427a0412addda8927fc56874730d9ff73c9a962c6a550d",
    },
};

#define INDEX_ALICE_PAST 0
#define INDEX_ALICE_PAST2 4
#define INDEX_ALICE_PAST3 3
#define INDEX_ALICE_FUTURE 1
#define INDEX_ALICE_FUTURE2 6
#define INDEX_ALICE_FUTURE3 5
#define INDEX_ALICE_NOW 2

mikey_sakke_key_material_t* setupKeyMaterial(char* user_uri, char* community, mikey_sakke_key_material_t* keys, key_material_values_t* keymat) {
    // Key retrieval from KMS

    if (keys == NULL) {
        keys = mikey_sakke_alloc_key_material("runtime:empty");
    }
    const char* user_id   = mikey_sakke_gen_user_id_format_2_for_period(user_uri, keymat->kms_uri, keymat->key_period, keymat->offset, keymat->key_period_no);
    mikey_sakke_add_community(keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(keys, community, "KPAK", keymat->kpak, false);
    mikey_sakke_provision_key_material(keys, community, "Z", keymat->z, false);
    mikey_sakke_provision_key_material(keys, user_id, "RSK", keymat->rsk, true);
    mikey_sakke_provision_key_material(keys, user_id, "SSK", keymat->ssk, true);
    mikey_sakke_provision_key_material(keys, user_id, "PVT", keymat->pvt, false);
    // clang-format on

    if (!mikey_sakke_validate_signing_keys(user_id, keys)) return NULL;

    mikey_sakke_set_public_parameter(keys, community, "UserKeyPeriod", libmutil::itoa(keymat->key_period).c_str());
    mikey_sakke_set_public_parameter(keys, community, "UserKeyOffset", libmutil::itoa(keymat->offset).c_str());
    mikey_sakke_set_public_parameter(keys, community, "KmsUri", keymat->kms_uri);
    mikey_sakke_set_public_parameter(keys, community, "SakkeSet", "1");

    if (!kms_key_material_set_period_no(keys, community, keymat->key_period_no)) return NULL;

    free((void*)user_id);
    return keys;
}

TEST(test_i_message_infer_key, test_i_message_infer_key_previous_to_timestamp) {
    // Encrypted in key_period_no 1518 (but with current_timestamp=1531) by gms@streamwide.com to alice.org.com
    std::string imsg_str = "mikey ARoFAQq2w58BAgQAAQAAAAgHwwNlCrbDnwsA7JaOjAAAAAAOECN0EGGAtCAJSLCsWvsiJ5gOCAEAINoIIp3171yj04BvvRkvNcUPhXoLsIYIs6w5lNCFsk10DgkBACAlhLE6ygBZUb3d2Wc1QlQ/6+7PGsQHDF7QZ6DFPUaRoQ4GAQAYa21zLmRldjQzLnN0cmVhbXdpZGUuY29tCgcBABhrbXMuZGV2NDMuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBJlwYXXFK0HQtO2k4A2Cx3PyKi3P572AYRGfEulFFBzdaukEOTV9xWFhZVcuApVlB22+fcCmcWRS5hdIw4Jtpmw9F9+XTjJ31KTtsP0DhpMhh9XvwILGmGj03N2oFZ9E+ybKibUEw0DEvDKjvFV5ZNA9rXCVgCSJW2BxCOad+59wWWHbVaKEPYQ2DpoToqtVx0QqJQlIWHaLfWhN6WO6xNcp/IBg5Kn/2qtsKHI6+JatnHl57/7SyY97RAq2g1Sh8Y/OVjRJrW+x1Bj/F4gM1LPvdZARodTyuDXZFewnYpiJD/lvz7+b+mSualkFRCQomCY480XrqRVLSkX1zLz50+K503gvU05tEk1aYiAFpTHjBAcAR0MAAAAAAQAAAAAAAc53KOZBt6ax4aS5EPxw/ZIKtsOfAAAkZNG91iqhgxq4YmNGwGvIe4I3+Ud7OFZulijRj/k/f7oJMk5OIIGgz+jS6i06VMzYOMURatBjn8F1l726xNRG4Zqs16O+ShPvS9bcOIpzCPAyXVn/4SSFhr5q7hWPWeEtScNt3j0ABAqOKVxiebPwepZiZf99RMdjJ+yzIMKqJKxVDe5Q8MIgXOLhRFLJX7i+1HWBRfUX4FRX2G6a5dwzW0A3qJDP7QE=";
    OctetString gmk_expected = OctetString::skipws("3112e49eaa4eaf234f3dd789ff1a7920");
    OctetString gmk_id_expected = OctetString::skipws("07c30365");
    char                        sender_uri[] = "gms@streamwide.com";
    char                        alice_uri[] = "alice@org.com";
    char                        community[] = "my.comm";
    mikey_key_mgmt_string_t     imsg;
    key_material_values_t*      keymat_now  = &(table_key_material[INDEX_ALICE_PAST2]);
    key_material_values_t*      keymat_past = &(table_key_material[INDEX_ALICE_PAST]);

    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("error");

    mikey_sakke_key_material_t* alice_keys  = setupKeyMaterial(alice_uri, community, NULL, keymat_now);
    ASSERT_TRUE(alice_keys != NULL);

    // Prepare
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);

    mikey_sakke_set_payload_signature_validation(alice, false);

    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_str.data();
    imsg.len = imsg_str.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);

    // Extract key_period_no from I-MESSAGE
    uint32_t key_period_extracted = mikey_sakke_get_key_period_no_from_imsg(alice_incoming, imsg, sender_uri);
    if (key_period_extracted != keymat_now->key_period_no) {
        MIKEY_SAKKE_LOGD("Expected: the inserted key-materials does not correspond to I-MESSAGE related key_period_no -> gather keymat and insert (simulate)");
        ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_past) != NULL);
    }

    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, sender_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);

    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_key_data_destroy(alice_gmk);

    return;
}

TEST(test_i_message_infer_key, test_i_message_infer_key_after_timestamp) {
    // Encrypted in key_period_no 1540 (but with current_timestamp=1531) by gms@streamwide.com to alice@org.com
    std::string imsg_str = "mikey ARoFAQY5iNUBAgQAAQAAAAgIObZ7BjmI1QsA7JodhQAAAAAOEHwANg9HAYcushVM7n9v3esOCAEAILWFDqm+SXpwWqeCvGJHv2Uqu10ZX5pxlrac3wG/I3HFDgkBACAXmARkTd31/ms7O5MWQi6WxTyAlXdpzdHduU4PAYwJ7A4GAQAYa21zLmRldjQzLnN0cmVhbXdpZGUuY29tCgcBABhrbXMuZGV2NDMuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBBAAvsQpPwtH8c/xfxsLCmJP0zBptpNG3uaZ/4JWTsWgAOrrypF8OAaLBcOroDliyIRzKIw33mm9c8199PR6OIfBFylpy4C9BeVub+2QriPZyTML96so5sYhxiBCT8Py95/TGIGO2CaVu3nrWMmQxwTl9Tn4oZOg2E8ajMK5ywYzJ0INOSMQZu0WY7wfX+VGL8UgWBmLnudLdnRHcT5xxfsQYR09uKs8aMKSrOhL7v+WJgUA9wxhv8j6QCanrfxs57lBiYSfUk9WKwuYWhoijAzeUFK3pefiimEcQlhbprkPirzjQMKjGSvkLHdh0c4MGpgfBRaXrWo95u9EBatO0wOjPiJrrK4aISMutT1DAm2VBAcAR0MAAAAAAQAAAAAAAXkwteVANwDpv9oZ3nq70yYGOYjVAAAknu0ux9XOZMz3+B8b7J3Nje0kJwJ3pr0NKcm7yjnAC5EU/OXmIIFCeLiXw+L3ivEGtVJmDCSeijoiQYxiwf2QBQuFb9xkRAc7qCUzdISSfAeZWeLmBVdUKqEeJjWD5n7a7Xw1FB06BJwY1WxEZS7+wlx3xpfioSSXvyMoTzLdKnnZxwbGc+maDocoik1dW1TPdQDksehh2V7oPAaPSP9AlHVOTZGxQ6E=";
    OctetString gmk_expected = OctetString::skipws("30fd0840ac6905666ce0f0e4f24aaa81");
    OctetString gmk_id_expected = OctetString::skipws("0839b67b");
    char                        sender_uri[] = "gms@streamwide.com";
    char                        alice_uri[] = "alice@org.com";
    char                        community[] = "my.comm";
    mikey_key_mgmt_string_t     imsg;
    key_material_values_t*      keymat_now  = &(table_key_material[INDEX_ALICE_PAST2]);
    key_material_values_t*      keymat_future = &(table_key_material[INDEX_ALICE_FUTURE]);

    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("error");

    mikey_sakke_key_material_t* alice_keys  = setupKeyMaterial(alice_uri, community, NULL, keymat_now);
    ASSERT_TRUE(alice_keys != NULL);

    // Prepare
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);

    mikey_sakke_set_payload_signature_validation(alice, false);

    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_str.data();
    imsg.len = imsg_str.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);

    // Extract key_period_no from I-MESSAGE
    uint32_t key_period_extracted = mikey_sakke_get_key_period_no_from_imsg(alice_incoming, imsg, sender_uri);
    if (key_period_extracted != keymat_now->key_period_no) {
        MIKEY_SAKKE_LOGD("Expected: the inserted key-materials does not correspond to I-MESSAGE related key_period_no -> gather keymat and insert (simulate)");
        ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_future) != NULL);
    }

    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, sender_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);

    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_key_data_destroy(alice_gmk);

    return;
}

TEST(test_i_message_infer_key, test_i_message_infer_key_previous_to_key_material) {
    // Encrypted in key_period_no 15 by gms@streamwide.com to alice@org.com
    std::string imsg_str = "mikey ARoFAQ+LULgBAgQAAQAAAAgFfT1RD4tQuAsA7JaQggAAAAAOEMtl56c8oI29n9gEBXvQOo8OCAEAIN30XOzzNPDNYJzDDFYGPYdRWSK5gIVHn1YZ6ewXtRkwDgkBACCX6IsQpgpXH0kWtFSDJwYwobvAqT2FoMNMvGksY1Sckg4GAQAYa21zLmRldjQzLnN0cmVhbXdpZGUuY29tCgcBABhrbXMuZGV2NDMuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBCS4TH2WS8vQety4V7FfI1ceK6TY+KzxXFbkyqZJO9HiFG+6zezQLeHcr+6cHhLQPDSPVR+izf2KKflcKRjHdrwWnynGdbQ76n1NW2O5lL/meoJpUm28V0w/6BeGIfOl57iSdj38W/mOM0s0XYhmuA7+Om0FI1UHIGL0qkFJQmOdJvhXkynxlcnFHfl60oNLuF0AJhi0GtJxqsWykWf0ygtraRVpxtSGxYY7Mw2OrrtPO5SY464TEe3SsWXhNDNtCslxsvGAvXmZJ5ANRGo3eTkEVaLSVqEY7D8k45PXxbYUk0/69qi6GTqAzSt6nCM8QMlLHd3evN52bEBJjNXLM7iMANXDk6OiqvSDuyffci3JBAcAR0MAAAAAAQAAAAAAATC7gKr0GNemj4lCSik7Y2YPi1C4AAAk7GzLllnJcABMHEeDgPy8y8XIWInGyVYJJpdswr5Cn/mrKLq+IIEXpTslQXHnQrztpYFd7gd8L2e/FdiKMOIDz7ECRU7/z62KOGF3AW73jETuyTCWJSG4Dwx1kBCmoKF//W2HjYfKBL4mPveYOtCea+uxMWeH3IZ9jbQ61OgXMebYe/Kbx+BA7Eipg2wD7Fn9GYadrRhDO7iFPdp7IQ4iVblcidjT62w=";
    OctetString gmk_expected = OctetString::skipws("896e3a7db6970e06e9377de53c1b9aa6");
    OctetString gmk_id_expected = OctetString::skipws("057d3d51");
    char                        sender_uri[] = "gms@streamwide.com";
    char                        alice_uri[] = "alice@org.com";
    char                        community[] = "my.comm";
    mikey_key_mgmt_string_t     imsg;
    key_material_values_t*      keymat_now     = &(table_key_material[INDEX_ALICE_PAST3]);
    key_material_values_t*      keymat_correct = &(table_key_material[INDEX_ALICE_PAST2]);

    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("error");

    mikey_sakke_key_material_t* alice_keys  = setupKeyMaterial(alice_uri, community, NULL, keymat_now);
    ASSERT_TRUE(alice_keys != NULL);

    // Prepare
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);

    mikey_sakke_set_payload_signature_validation(alice, false);

    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_str.data();
    imsg.len = imsg_str.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);

    // Extract key_period_no from I-MESSAGE
    uint32_t key_period_extracted = mikey_sakke_get_key_period_no_from_imsg(alice_incoming, imsg, sender_uri);
    if (key_period_extracted != keymat_now->key_period_no) {
        MIKEY_SAKKE_LOGD("Expected: the inserted key-materials does not correspond to I-MESSAGE related key_period_no -> gather keymat and insert (simulate)");
        ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_correct) != NULL);
    }

    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, sender_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);

    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_key_data_destroy(alice_gmk);

    return;
}

TEST(test_i_message_infer_key, test_i_message_infer_key_after_key_material) {
    // Encrypted in key_period_no 1657 by gms@streamwide.com to alice@org.com
    std::string imsg_str = "mikey ARoFAQnS1/4BAgQAAQAAAAgKN7cxCdLX/gsA7JaWpAAAAAAOEBpvdx0rQPF71YU4vU8fVv0OCAEAIEBMf+5td+fBOtiHHjQj+//asyrntjak2izgEDi2kunvDgkBACBAskpRodRiuBagPEvcJu1N6rfYbOyr/CeC4FkARiOzkg4GAQAYa21zLmRldjQzLnN0cmVhbXdpZGUuY29tCgcBABhrbXMuZGV2NDMuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBC057M5pw1dryagGOmOt/q9BN4hECWLDsB5tF/qPEsy/x+P0ty/fUBweStEO9YakzKwo+26GZKncvH3r/dnypCtLxIZ+4sdU6VDVnIc37sOKv8oNAp5DWuO7fDU8Mi4zzFv3Cv8EKwiqify0LFcJtjVsqABzwKsjsLS+3a9m36KJAUB8iO2ZwmOO3ip90mDcQVHqIRrSS0fOnX7JWo+FHXBHSVW9Bz527gXOaFyEkq7R9z3Zzxn6OgdC66kZuw7/GwVX3Aona0W9uYIq+r39UsW3YCMSiMmunHy2ysGwEzaXYhgqvi6pKNYprmqnNyxDl231i/Z5DCIORpwv+FuVKX2DnNwhyxDyMjSVBdhjeU+HBAcAR0MAAAAAAQAAAAAAAZ7whkO6iRChCCCuSb/vQzIJ0tf+AAAk+RDtqRc4Xy9vLFrNxBqvgJd4ehcdeJU5wasa22hxacBdYb3MIIFeKBnwu8pxDXGEKy6optI84eQmuc9A64FMqEmKcDX3WAZnotCP5v2mzWbz/e1K8dGA9yIoT5b9ACbMYMQWyuFDBFrjvYri6/MXHQb7zgRemgSgiRQfjjHW3i2EmJX1o5tvR3tWVYl5wQuk82sOxpkHPuqKEOZplkmqeDGpG9v1Ur8=";
    OctetString gmk_expected = OctetString::skipws("e5e2339e643435252d2b670bc6c78db8");
    OctetString gmk_id_expected = OctetString::skipws("0a37b731");
    char                        sender_uri[] = "gms@streamwide.com";
    char                        alice_uri[] = "alice@org.com";
    char                        community[] = "my.comm";
    mikey_key_mgmt_string_t     imsg;
    key_material_values_t*      keymat_now     = &(table_key_material[INDEX_ALICE_FUTURE3]);
    key_material_values_t*      keymat_correct = &(table_key_material[INDEX_ALICE_FUTURE2]);

    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("error");

    mikey_sakke_key_material_t* alice_keys  = setupKeyMaterial(alice_uri, community, NULL, keymat_now);
    ASSERT_TRUE(alice_keys != NULL);

    // Prepare
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);

    mikey_sakke_set_payload_signature_validation(alice, false);

    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_str.data();
    imsg.len = imsg_str.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);

    // Extract key_period_no from I-MESSAGE
    uint32_t key_period_extracted = mikey_sakke_get_key_period_no_from_imsg(alice_incoming, imsg, sender_uri);
    if (key_period_extracted != keymat_now->key_period_no) {
        MIKEY_SAKKE_LOGD("Expected: the inserted key-materials does not correspond to I-MESSAGE related key_period_no -> gather keymat and insert (simulate)");
        ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_correct) != NULL);
    }

    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, sender_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);

    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_key_data_destroy(alice_gmk);

    return;
}

TEST(test_i_message_infer_key, test_i_message_infer_key_auto_download) {
    // Encrypted in key_period_no 1657 by gms@streamwide.com to alice@org.com
    std::string imsg_str = "mikey ARoFAQnS1/4BAgQAAQAAAAgKN7cxCdLX/gsA7JaWpAAAAAAOEBpvdx0rQPF71YU4vU8fVv0OCAEAIEBMf+5td+fBOtiHHjQj+//asyrntjak2izgEDi2kunvDgkBACBAskpRodRiuBagPEvcJu1N6rfYbOyr/CeC4FkARiOzkg4GAQAYa21zLmRldjQzLnN0cmVhbXdpZGUuY29tCgcBABhrbXMuZGV2NDMuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBC057M5pw1dryagGOmOt/q9BN4hECWLDsB5tF/qPEsy/x+P0ty/fUBweStEO9YakzKwo+26GZKncvH3r/dnypCtLxIZ+4sdU6VDVnIc37sOKv8oNAp5DWuO7fDU8Mi4zzFv3Cv8EKwiqify0LFcJtjVsqABzwKsjsLS+3a9m36KJAUB8iO2ZwmOO3ip90mDcQVHqIRrSS0fOnX7JWo+FHXBHSVW9Bz527gXOaFyEkq7R9z3Zzxn6OgdC66kZuw7/GwVX3Aona0W9uYIq+r39UsW3YCMSiMmunHy2ysGwEzaXYhgqvi6pKNYprmqnNyxDl231i/Z5DCIORpwv+FuVKX2DnNwhyxDyMjSVBdhjeU+HBAcAR0MAAAAAAQAAAAAAAZ7whkO6iRChCCCuSb/vQzIJ0tf+AAAk+RDtqRc4Xy9vLFrNxBqvgJd4ehcdeJU5wasa22hxacBdYb3MIIFeKBnwu8pxDXGEKy6optI84eQmuc9A64FMqEmKcDX3WAZnotCP5v2mzWbz/e1K8dGA9yIoT5b9ACbMYMQWyuFDBFrjvYri6/MXHQb7zgRemgSgiRQfjjHW3i2EmJX1o5tvR3tWVYl5wQuk82sOxpkHPuqKEOZplkmqeDGpG9v1Ur8=";
    OctetString gmk_expected = OctetString::skipws("e5e2339e643435252d2b670bc6c78db8");
    OctetString gmk_id_expected = OctetString::skipws("0a37b731");
    char                        sender_uri[] = "gms@streamwide.com";
    char                        alice_uri[] = "alice@org.com";
    char                        community[] = "my.comm";
    mikey_key_mgmt_string_t     imsg;
    key_material_values_t*      keymat_now      = &(table_key_material[INDEX_ALICE_FUTURE3]);
    key_material_values_t*      keymat_correct  = &(table_key_material[INDEX_ALICE_FUTURE2]);
    key_material_values_t*      keymat_other    = &(table_key_material[INDEX_ALICE_PAST]);
    const char                  token[]         = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtaEZNb2xodlpNVXUwT01xYjhZY2dXc0hUMEFlQ0l5cERnR2ZPV1d2SlUwIn0.eyJleHAiOjE4NTQ3NTczNzEsImlhdCI6MTc1NDY3MDk3MSwianRpIjoiN2VjNjc1NjEtNmJjYS00YmFkLTg3MTUtOGE0ZmZjMzRhMTA3IiwiaXNzIjoiaHR0cHM6Ly9vcGVuaWQuc3RyZWFtd2lkZS5jb20vYXV0aC9yZWFsbXMvRGV2UmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiZWMwNWM3YzMtZWU4NS00ZjdjLWEyMGQtYmYyNmE1MzVhMjk2IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9iaWxlLWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJhMTc2ODA2OS1iZWNlLTQ5NTAtOTI0MS02OWRmMDViMzYyZmQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtZGV2cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBvcGVuaWQgcHJvZmlsZSAzZ3BwOm1jcHR0OnB0dF9zZXJ2ZXIiLCJzaWQiOiJhMTc2ODA2OS1iZWNlLTQ5NTAtOTI0MS02OWRmMDViMzYyZmQiLCJtY3B0dF9pZCI6ImFsaWNlQG9yZy5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IldlYiBDaGF0IiwicHJlZmVycmVkX3VzZXJuYW1lIjoicmJvbmFteV82NjYwMDAxMTEiLCJnaXZlbl9uYW1lIjoiV2ViIiwiZmFtaWx5X25hbWUiOiJDaGF0IiwiY2xpZW50X2lkIjoibWNwdHRfY2xpZW50IiwiZW1haWwiOiJyYm9uYW15KzY2NjAwMDExMUBzdHJlYW13aWRlLmNvbSJ9Cg.Q97rv-RB3QWxqpt-Wr4N3D-fm_QJo2XN9Q0Uz5esx_tysefS2cA_9egFSgvAlxC5hsyjbpr8ErRwLvMPtjg0XTxVcJBdMPEmKtwQqpmExKD3gtDK350vY3y4XV6zwEgVc9lML8xDfPaWbiKZg5_3lbusX5wG6UduILVJNGv9ftPhSKup9lRcCpkMBZZubRx8v9mAlE_giWb6wuUxW1sq3cD-ztdBsUhyiiJsYbobyPzl2q7ht6m5rFERRN8keu6IzdnMeLXxhto4LxOdAiW5laN-jSF8jUh5r70-3NuXzlkC0Jb4U_ID9AGvu5AA-BHnC13wbtb05ekySX6qxe22vA";
    const char                  kms_uri[]       = "https://127.0.0.1";

    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("error");

    mikey_sakke_key_material_t* alice_keys  = setupKeyMaterial(alice_uri, community, NULL, keymat_now);
    ASSERT_TRUE(alice_keys != NULL);

    // Prepare
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);

    mikey_sakke_set_payload_signature_validation(alice, false);

    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_str.data();
    imsg.len = imsg_str.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);


    // Setup KMS client in auto-download
#ifdef HTTP_REQUEST_BY_CALLBACK
    km_client_t*                kms_client = mikey_sakke_client_create(kms_uri, false, alice_keys);
    request_curl_t              extra = {enable_tls: true, tls_verify_peer: false, tls_verify_host: false};
    if (memcmp(kms_uri, "http://", 7) == 0) {
        extra.enable_tls = false;
    }
    MIKEY_SAKKE_LOGD("Request keys: tls_enabled: %d / verify_host: %d / verify_peer: %d", extra.enable_tls, extra.tls_verify_host, extra.tls_verify_peer);
    mikey_sakke_set_http_request_func(kms_client, &executeHttpRequestCurl, (void*)&extra);
#else
    km_client_t*                kms_client = mikey_sakke_client_create(kms_uri, false, alice_keys, 10000);
    mikey_sakke_client_set_tls_security(kms_client, false, false);
#endif
    mikey_sakke_client_set_user_uri(kms_client, alice_uri);
    mikey_sakke_client_set_token(kms_client, token);
    mikey_sakke_set_key_material_auto_download(alice_incoming, kms_client, true);

    //ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_correct) != NULL);
    //ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_other) != NULL);
    // Processing the download of keys
    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, sender_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);

    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_key_data_destroy(alice_gmk);
    mikey_sakke_client_destroy(kms_client);

    return;
}

TEST(test_i_message_infer_key, test_i_message_infer_key_auto_download_no_keys) {
    // Encrypted in key_period_no 1657 by gms@streamwide.com to alice@org.com
    std::string imsg_str = "mikey ARoFAQnS1/4BAgQAAQAAAAgKN7cxCdLX/gsA7JaWpAAAAAAOEBpvdx0rQPF71YU4vU8fVv0OCAEAIEBMf+5td+fBOtiHHjQj+//asyrntjak2izgEDi2kunvDgkBACBAskpRodRiuBagPEvcJu1N6rfYbOyr/CeC4FkARiOzkg4GAQAYa21zLmRldjQzLnN0cmVhbXdpZGUuY29tCgcBABhrbXMuZGV2NDMuc3RyZWFtd2lkZS5jb20aAAAAGwABBgEBEAIBBAQBDAUBAAYBABIBBBMBABQBEBUBAgERBC057M5pw1dryagGOmOt/q9BN4hECWLDsB5tF/qPEsy/x+P0ty/fUBweStEO9YakzKwo+26GZKncvH3r/dnypCtLxIZ+4sdU6VDVnIc37sOKv8oNAp5DWuO7fDU8Mi4zzFv3Cv8EKwiqify0LFcJtjVsqABzwKsjsLS+3a9m36KJAUB8iO2ZwmOO3ip90mDcQVHqIRrSS0fOnX7JWo+FHXBHSVW9Bz527gXOaFyEkq7R9z3Zzxn6OgdC66kZuw7/GwVX3Aona0W9uYIq+r39UsW3YCMSiMmunHy2ysGwEzaXYhgqvi6pKNYprmqnNyxDl231i/Z5DCIORpwv+FuVKX2DnNwhyxDyMjSVBdhjeU+HBAcAR0MAAAAAAQAAAAAAAZ7whkO6iRChCCCuSb/vQzIJ0tf+AAAk+RDtqRc4Xy9vLFrNxBqvgJd4ehcdeJU5wasa22hxacBdYb3MIIFeKBnwu8pxDXGEKy6optI84eQmuc9A64FMqEmKcDX3WAZnotCP5v2mzWbz/e1K8dGA9yIoT5b9ACbMYMQWyuFDBFrjvYri6/MXHQb7zgRemgSgiRQfjjHW3i2EmJX1o5tvR3tWVYl5wQuk82sOxpkHPuqKEOZplkmqeDGpG9v1Ur8=";
    OctetString gmk_expected = OctetString::skipws("e5e2339e643435252d2b670bc6c78db8");
    OctetString gmk_id_expected = OctetString::skipws("0a37b731");
    char                        sender_uri[] = "gms@streamwide.com";
    char                        alice_uri[] = "alice@org.com";
    char                        community[] = "my.comm";
    mikey_key_mgmt_string_t     imsg;
    const char                  token[]         = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtaEZNb2xodlpNVXUwT01xYjhZY2dXc0hUMEFlQ0l5cERnR2ZPV1d2SlUwIn0.eyJleHAiOjE4NTQ3NTczNzEsImlhdCI6MTc1NDY3MDk3MSwianRpIjoiN2VjNjc1NjEtNmJjYS00YmFkLTg3MTUtOGE0ZmZjMzRhMTA3IiwiaXNzIjoiaHR0cHM6Ly9vcGVuaWQuc3RyZWFtd2lkZS5jb20vYXV0aC9yZWFsbXMvRGV2UmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiZWMwNWM3YzMtZWU4NS00ZjdjLWEyMGQtYmYyNmE1MzVhMjk2IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9iaWxlLWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJhMTc2ODA2OS1iZWNlLTQ5NTAtOTI0MS02OWRmMDViMzYyZmQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtZGV2cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBvcGVuaWQgcHJvZmlsZSAzZ3BwOm1jcHR0OnB0dF9zZXJ2ZXIiLCJzaWQiOiJhMTc2ODA2OS1iZWNlLTQ5NTAtOTI0MS02OWRmMDViMzYyZmQiLCJtY3B0dF9pZCI6ImFsaWNlQG9yZy5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IldlYiBDaGF0IiwicHJlZmVycmVkX3VzZXJuYW1lIjoicmJvbmFteV82NjYwMDAxMTEiLCJnaXZlbl9uYW1lIjoiV2ViIiwiZmFtaWx5X25hbWUiOiJDaGF0IiwiY2xpZW50X2lkIjoibWNwdHRfY2xpZW50IiwiZW1haWwiOiJyYm9uYW15KzY2NjAwMDExMUBzdHJlYW13aWRlLmNvbSJ9Cg.Q97rv-RB3QWxqpt-Wr4N3D-fm_QJo2XN9Q0Uz5esx_tysefS2cA_9egFSgvAlxC5hsyjbpr8ErRwLvMPtjg0XTxVcJBdMPEmKtwQqpmExKD3gtDK350vY3y4XV6zwEgVc9lML8xDfPaWbiKZg5_3lbusX5wG6UduILVJNGv9ftPhSKup9lRcCpkMBZZubRx8v9mAlE_giWb6wuUxW1sq3cD-ztdBsUhyiiJsYbobyPzl2q7ht6m5rFERRN8keu6IzdnMeLXxhto4LxOdAiW5laN-jSF8jUh5r70-3NuXzlkC0Jb4U_ID9AGvu5AA-BHnC13wbtb05ekySX6qxe22vA";
    const char                  kms_uri[]       = "https://127.0.0.1";

    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("error");

    mikey_sakke_key_material_t* alice_keys  = mikey_sakke_alloc_key_material("runtime:empty");
    ASSERT_TRUE(alice_keys != NULL);
    mikey_sakke_add_community(alice_keys, community);
    // To orientate the infer to the correct direction
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(1650).c_str());

    // Prepare
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);

    //mikey_sakke_set_payload_signature_validation(alice, false);

    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_str.data();
    imsg.len = imsg_str.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);


    // Setup KMS client in auto-download
#ifdef HTTP_REQUEST_BY_CALLBACK
    km_client_t*                kms_client = mikey_sakke_client_create(kms_uri, false, alice_keys);
    request_curl_t              extra = {enable_tls: true, tls_verify_peer: false, tls_verify_host: false};
    if (memcmp(kms_uri, "http://", 7) == 0) {
        extra.enable_tls = false;
    }
    MIKEY_SAKKE_LOGD("Request keys: tls_enabled: %d / verify_host: %d / verify_peer: %d", extra.enable_tls, extra.tls_verify_host, extra.tls_verify_peer);
    mikey_sakke_set_http_request_func(kms_client, &executeHttpRequestCurl, (void*)&extra);
#else
    km_client_t*                kms_client = mikey_sakke_client_create(kms_uri, false, alice_keys, 10000);
    mikey_sakke_client_set_tls_security(kms_client, false, false);
#endif
    mikey_sakke_client_set_user_uri(kms_client, alice_uri);
    mikey_sakke_client_set_token(kms_client, token);
    mikey_sakke_set_key_material_auto_download(alice_incoming, kms_client, true);

    //ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_correct) != NULL);
    //ASSERT_TRUE(setupKeyMaterial(alice_uri, community, alice_keys, keymat_other) != NULL);
    // Processing the download of keys
    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, sender_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);

    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_key_data_destroy(alice_gmk);
    mikey_sakke_client_destroy(kms_client);

    return;
}