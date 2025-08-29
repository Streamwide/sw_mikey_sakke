#include "keymaterials.h"
#include "libmutil/Logger.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <cinttypes>
#include <libmikey/Mikey.h>
#include <sstream>
#include <util/octet-string.h>

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

// Developper note : since to generate I-Messages, we will mainly be using the C API, the unit test will be done using that same API

TEST(test_i_message, i_message_gmk) {
    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char community[]     = "streamwide.com";
    uint8_t*   gmk             = mikey_sakke_gen_key(16);
    uint8_t*   gmk_id          = mikey_sakke_gen_key_id(GMK);
    const char kms_uri[]       = STW_KMS_URI;
    uint32_t   user_key_period = 2592000;
    uint32_t   user_key_offset = 0;
    
    // DO NOT CHANGE THE KEY PERIOD NO : KEYS WILL VALIDATE ONLY FOR THIS PERIOD
    const uint32_t key_period_no = 1490;

    auto os1 = OctetString {16, gmk};
    auto os2 = OctetString {4, gmk_id};

    MIKEY_SAKKE_LOGD("GMK : %s", os1.translate().c_str());
    MIKEY_SAKKE_LOGD("GMK-ID : %s", os2.translate().c_str());

    // GMS INIT
    const char gms_uri[] = "alice@org.com"; // For now, the KMS generates all keys for alice@org.com

    mikey_sakke_key_material_t* gms_keys = mikey_sakke_alloc_key_material("runtime:empty");

    const char* gms_id = mikey_sakke_gen_user_id_format_2_for_period(gms_uri, kms_uri, user_key_period, user_key_offset, key_period_no);
    // 35bad79faa9b23bf1656a5dbead20cd5226a75453ee470201e280dd6f8fb6e70

    mikey_sakke_add_community(gms_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(gms_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(gms_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(gms_id, gms_keys));

    // Set community params in GMS keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(gms_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(gms_keys, community, "SakkeSet", "1");
    }

    // Alice INIT
    const char alice_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* alice_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* alice_id = mikey_sakke_gen_user_id_format_2_for_period(alice_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(alice_keys, community);

    // clang-format off

    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on

    // Set community params in Alice keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    }

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(alice_id, alice_keys));

    // Bob INIT
    const char bob_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* bob_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* bob_id = mikey_sakke_gen_user_id_format_2_for_period(bob_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(bob_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(bob_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(bob_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on

    // Set community params in Bob keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(bob_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(bob_keys, community, "SakkeSet", "1");
    }

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(bob_id, bob_keys));

    // Generate I_MESSAGE from GMS to Alice
    mikey_sakke_user_t* gms          = mikey_sakke_alloc_user(gms_uri, gms_keys);
    mikey_sakke_call_t* gms_outgoing = mikey_sakke_alloc_call(gms);
    mikey_sakke_add_sender_stream(gms_outgoing, 0xcafebabe);

    struct key_agreement_params* params     = key_agreement_params_create(GMK, 16, gmk, 4, gmk_id, 0, nullptr);
    mikey_key_mgmt_string_t      init_alice = mikey_sakke_group_init(gms_outgoing, alice_uri, params);

    MIKEY_SAKKE_LOGD("GMS sends to Alice : %s", init_alice.ptr);

    // Reuse the same RAND
    unsigned int   rand_length = 0;
    const uint8_t* rand        = mikey_sakke_get_mikey_rand(gms_outgoing, &rand_length);

    // Generate I_MESSAGE from GMS to Bob
    struct key_agreement_params* params_group = key_agreement_params_create(GMK, 16, gmk, 4, gmk_id, rand_length, rand);
    mikey_key_mgmt_string_t      init_bob     = mikey_sakke_group_init(gms_outgoing, bob_uri, params_group);

    MIKEY_SAKKE_LOGD("GMS sends to Bob : %s", init_bob.ptr);

    // Alice receives the call...
    mikey_sakke_user_t* alice          = mikey_sakke_alloc_user(alice_uri, alice_keys);
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);
    // Bob receives the call...
    mikey_sakke_user_t* bob          = mikey_sakke_alloc_user(bob_uri, bob_keys);
    mikey_sakke_call_t* bob_incoming = mikey_sakke_alloc_call(bob);
    mikey_sakke_add_sender_stream(bob_incoming, 0xdeadbeef);


    // Gather key_id without decrypting
    mikey_sakke_key_id_t    keyid_only;
    mikey_sakke_key_id_from_imessage(&keyid_only, &init_alice);
    //printf("Compare: %d\n", memcmp(gmk_id, keyid_only.key_id, keyid_only.key_id_size));
    //ASSERT_EQ(memcmp(gmk_id, keyid_only.key_id, 4), 0);
    free(keyid_only.key_id);
    MIKEY_SAKKE_LOGD("Alice successfuly extract key ID from Bob IMESSAGE");
    mikey_sakke_key_id_from_imessage(&keyid_only, &init_bob);
    //ASSERT_EQ(memcmp(gmk_id, keyid_only.key_id, 4), 0);
    free(keyid_only.key_id);
    MIKEY_SAKKE_LOGD("Bob successfuly extract key ID from Alice IMESSAGE");
    
    // Alice authenticates the MIKEY SAKKE OFFER from the GMS
    bool init_auth_alice = mikey_sakke_uas_auth(alice_incoming, init_alice, gms_uri, nullptr);
    ASSERT_TRUE(init_auth_alice);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    MIKEY_SAKKE_LOGD("Alice successfuly authenticated MIKEY SAKKE OFFER");

    // Bob authenticates the MIKEY SAKKE OFFER from the GMS
    bool init_auth_bob = mikey_sakke_uas_auth(bob_incoming, init_bob, gms_uri, nullptr);
    ASSERT_TRUE(init_auth_bob);
    ASSERT_TRUE(mikey_sakke_call_is_secured(bob_incoming));
    MIKEY_SAKKE_LOGD("Bob successfuly authenticated MIKEY SAKKE OFFER");

    // Alice retrieves GMK-Data from I-Message
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, 16U);
    ASSERT_EQ(memcmp(gmk, alice_gmk->key, alice_gmk->key_size), 0);

    ASSERT_EQ(alice_gmk->key_id_size, 4U);
    ASSERT_EQ(memcmp(gmk_id, alice_gmk->key_id, alice_gmk->key_id_size), 0);

    ASSERT_EQ(alice_gmk->rand_size, 16U);
    ASSERT_EQ(memcmp(rand, alice_gmk->rand, alice_gmk->rand_size), 0);

    // Bob retrieves GMK-DATA from I_Message
    struct mikey_sakke_key_data* bob_gmk = mikey_sakke_get_key_data(bob_incoming);
    ASSERT_EQ(bob_gmk->key_size, 16U);
    ASSERT_EQ(memcmp(gmk, bob_gmk->key, bob_gmk->key_size), 0);

    ASSERT_EQ(bob_gmk->key_id_size, 4U);
    ASSERT_EQ(memcmp(gmk_id, bob_gmk->key_id, bob_gmk->key_id_size), 0);

    ASSERT_EQ(bob_gmk->rand_size, 16U);
    ASSERT_EQ(memcmp(rand, bob_gmk->rand, bob_gmk->rand_size), 0);

    mikey_sakke_free_key_mgmt_string(init_alice);
    mikey_sakke_free_key_mgmt_string(init_bob);
    mikey_sakke_free_call(gms_outgoing);
    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_call(bob_incoming);
    mikey_sakke_free_user(gms);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_user(bob);
    mikey_sakke_free_key_material(gms_keys);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_free_key_material(bob_keys);
    free(gmk);
    free(gmk_id);
    free((char*)gms_id);
    free((char*)alice_id);
    free((char*)bob_id);
    key_agreement_params_delete(params);
    key_agreement_params_delete(params_group);
    free((uint8_t*)rand);
    mikey_sakke_key_data_destroy(alice_gmk);
    mikey_sakke_key_data_destroy(bob_gmk);
}

TEST(test_i_message, i_message_csk) {
    mikey_sakke_set_log_level("debug");

    const char community[]     = "streamwide.com";
    uint8_t*   csk             = mikey_sakke_gen_key(16);
    uint8_t*   csk_id          = mikey_sakke_gen_key_id(CSK);
    uint8_t*   csk_rand        = mikey_sakke_gen_key(16);
    const char kms_uri[]       = STW_KMS_URI;
    uint32_t   user_key_period = 2592000;
    uint32_t   user_key_offset = 0;
    // DO NOT CHANGE THE KEY PERIOD NO : KEYS WILL VALIDATE ONLY FOR THIS PERIOD
    const uint32_t key_period_no = 1490;

    auto os1 = OctetString {16, csk};
    auto os2 = OctetString {4, csk_id};

    MIKEY_SAKKE_LOGD("CSK : %s", os1.translate().c_str());
    MIKEY_SAKKE_LOGD("CSK-ID : %s", os2.translate().c_str());

    // Alice INIT
    const char alice_uri[] = "alice@org.com"; // For now, the KMS generates all keys for alice@org.com

    mikey_sakke_key_material_t* alice_keys = mikey_sakke_alloc_key_material("runtime:empty");

    const char* alice_id = mikey_sakke_gen_user_id_format_2_for_period(alice_uri, kms_uri, user_key_period, user_key_offset, key_period_no);
    // 35bad79faa9b23bf1656a5dbead20cd5226a75453ee470201e280dd6f8fb6e70

    mikey_sakke_add_community(alice_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(alice_id, alice_keys));
    // Set community params in alice keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    }

    // GMS INIT
    const char gms_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* gms_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* gms_id = mikey_sakke_gen_user_id_format_2_for_period(gms_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(gms_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(gms_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(gms_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on

    // Set community params in Alice keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(gms_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(gms_keys, community, "SakkeSet", "1");
    }

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(gms_id, gms_keys));

    // Generate I_MESSAGE from Alice to GMS
    mikey_sakke_user_t* alice          = mikey_sakke_alloc_user(alice_uri, alice_keys);
    mikey_sakke_call_t* alice_outgoing = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_outgoing, 0xcafebabe);

    struct key_agreement_params* params = key_agreement_params_create(CSK, 16, csk, 4, csk_id, 16, csk_rand);
    ASSERT_NE(params, nullptr);
    mikey_key_mgmt_string_t init_gms = mikey_sakke_group_init(alice_outgoing, gms_uri, params);

    MIKEY_SAKKE_LOGD("Alice sends to GMS : %s", init_gms.ptr);

    // GMS receives the message...
    mikey_sakke_user_t* gms          = mikey_sakke_alloc_user(gms_uri, gms_keys);
    mikey_sakke_call_t* gms_incoming = mikey_sakke_alloc_call(gms);
    mikey_sakke_add_sender_stream(gms_incoming, 0xdeadbeef);

    // Gather key_id without decrypting
    mikey_sakke_key_id_t    keyid_only;
    mikey_sakke_key_id_from_imessage(&keyid_only, &init_gms);
    ASSERT_EQ(memcmp(csk_id, keyid_only.key_id, sizeof(*csk_id)), 0);
    MIKEY_SAKKE_LOGD("GMS successfuly extract key ID from alice IMESSAGE");

    // GMS authenticates the MIKEY SAKKE OFFER from Alice
    bool init_auth_gms = mikey_sakke_uas_auth(gms_incoming, init_gms, alice_uri, nullptr);
    ASSERT_TRUE(init_auth_gms);
    ASSERT_TRUE(mikey_sakke_call_is_secured(gms_incoming));
    MIKEY_SAKKE_LOGD("GMS successfuly authenticated MIKEY SAKKE OFFER");

    // Extract CSK/ID/RAND
    struct mikey_sakke_key_data* alice_csk = mikey_sakke_get_key_data(gms_incoming);

    ASSERT_EQ(alice_csk->key_size, 16U);
    ASSERT_EQ(memcmp(csk, alice_csk->key, alice_csk->key_size), 0);

    ASSERT_EQ(alice_csk->key_id_size, 4U);
    ASSERT_EQ(memcmp(csk_id, alice_csk->key_id, alice_csk->key_id_size), 0);

    ASSERT_EQ(alice_csk->rand_size, 16U);
    ASSERT_EQ(memcmp(csk_rand, alice_csk->rand, alice_csk->rand_size), 0);

    mikey_sakke_free_key_mgmt_string(init_gms);
    mikey_sakke_free_call(alice_outgoing);
    mikey_sakke_free_call(gms_incoming);
    mikey_sakke_free_user(gms);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(gms_keys);
    mikey_sakke_free_key_material(alice_keys);
    free(csk);
    free(csk_id);
    free((char*)gms_id);
    free((char*)alice_id);
    free(keyid_only.key_id);
    key_agreement_params_delete(params);
    free((uint8_t*)csk_rand);
    mikey_sakke_key_data_destroy(alice_csk);
}

/* Alice is sending a PCK to Bob */
TEST(test_i_message, i_message_pck) {
    //mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char community[]     = "streamwide.com";
    uint8_t*   pck             = mikey_sakke_gen_key(16);
    uint8_t*   pck_id          = mikey_sakke_gen_key_id(PCK);
    uint8_t*   pck_rand        = mikey_sakke_gen_key(16);
    const char kms_uri[]       = STW_KMS_URI;
    uint32_t   user_key_period = 2592000;
    uint32_t   user_key_offset = 0;
    // DO NOT CHANGE THE KEY PERIOD NO : KEYS WILL VALIDATE ONLY FOR THIS PERIOD
    const uint32_t key_period_no = 1490;

    auto os1 = OctetString {16, pck};
    auto os2 = OctetString {4, pck_id};

    MIKEY_SAKKE_LOGD("PCK : %s", os1.translate().c_str());
    MIKEY_SAKKE_LOGD("PCK-ID : %s", os2.translate().c_str());

    // Alice INIT
    const char alice_uri[] = "alice@org.com"; // For now, the KMS generates all keys for alice@org.com

    mikey_sakke_key_material_t* alice_keys = mikey_sakke_alloc_key_material("runtime:empty");

    const char* alice_id = mikey_sakke_gen_user_id_format_2_for_period(alice_uri, kms_uri, user_key_period, user_key_offset, key_period_no);
    // 35bad79faa9b23bf1656a5dbead20cd5226a75453ee470201e280dd6f8fb6e70

    mikey_sakke_add_community(alice_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(alice_id, alice_keys));
    // Set community params in alice keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    }

    // BOB INIT
    const char bob_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* bob_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* bob_id = mikey_sakke_gen_user_id_format_2_for_period(bob_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(bob_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(bob_keys, community, "KPAK", STW_KEYMAT_KPAK, false);
    mikey_sakke_provision_key_material(bob_keys, community, "Z", STW_KEYMAT_Z, false);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "RSK", STW_KEYMAT_RSK_GMS, true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "SSK", STW_KEYMAT_SSK_GMS, true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "PVT", STW_KEYMAT_PVT_GMS, false);
    // clang-format on

    // Set community params in Alice keystore
    {
        std::stringstream ss;
        ss << user_key_period;
        mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriod", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << user_key_offset;
        mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyOffset", ss.str().c_str());
        ss.str(std::string());
        ss.clear();
        ss << key_period_no;
        mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriodNoSet", ss.str().c_str());
        mikey_sakke_set_public_parameter(bob_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(bob_keys, community, "SakkeSet", "1");
    }

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(bob_id, bob_keys));

    // Generate I_MESSAGE from Alice to BOB
    mikey_sakke_user_t* alice          = mikey_sakke_alloc_user(alice_uri, alice_keys);
    mikey_sakke_call_t* alice_outgoing = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_outgoing, 0xcafebabe);

    struct key_agreement_params* params = key_agreement_params_create(PCK, 16, pck, 4, pck_id, 16, pck_rand);
    ASSERT_NE(params, nullptr);
    mikey_key_mgmt_string_t init_bob = mikey_sakke_group_init(alice_outgoing, bob_uri, params);

    MIKEY_SAKKE_LOGD("Alice sends to Bob : %s", init_bob.ptr);

    // Bob receives the message...
    mikey_sakke_user_t* bob          = mikey_sakke_alloc_user(bob_uri, bob_keys);
    mikey_sakke_call_t* bob_incoming = mikey_sakke_alloc_call(bob);
    mikey_sakke_add_sender_stream(bob_incoming, 0xdeadbeef);

    // Gather key_id without decrypting
    mikey_sakke_key_id_t    keyid_only;
    mikey_sakke_key_id_from_imessage(&keyid_only, &init_bob);
    ASSERT_EQ(memcmp(pck_id, keyid_only.key_id, sizeof(*pck_id)), 0);
    MIKEY_SAKKE_LOGD("Bob successfuly extract key ID from alice IMESSAGE");

    // Bob authenticates the MIKEY SAKKE OFFER from Alice
    bool init_auth_gms = mikey_sakke_uas_auth(bob_incoming, init_bob, alice_uri, nullptr);
    ASSERT_TRUE(init_auth_gms);
    ASSERT_TRUE(mikey_sakke_call_is_secured(bob_incoming));
    MIKEY_SAKKE_LOGD("Bob successfuly authenticated MIKEY SAKKE OFFER");

    // Extract PCK/ID/RAND
    struct mikey_sakke_key_data* alice_pck = mikey_sakke_get_key_data(bob_incoming);

    ASSERT_TRUE(alice_pck);
    if (alice_pck) {
        ASSERT_EQ(alice_pck->key_size, 16U);
        ASSERT_EQ(memcmp(pck, alice_pck->key, alice_pck->key_size), 0);

        ASSERT_EQ(alice_pck->key_id_size, 4U);
        ASSERT_EQ(memcmp(pck_id, alice_pck->key_id, alice_pck->key_id_size), 0);

        ASSERT_EQ(alice_pck->rand_size, 16U);
        ASSERT_EQ(memcmp(pck_rand, alice_pck->rand, alice_pck->rand_size), 0);
    }

    if (init_bob.ptr) {
        mikey_sakke_free_key_mgmt_string(init_bob);
    }
    mikey_sakke_free_call(alice_outgoing);
    mikey_sakke_free_call(bob_incoming);
    mikey_sakke_free_user(bob);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_key_material(bob_keys);
    mikey_sakke_free_key_material(alice_keys);
    free(pck);
    free(pck_id);
    free((char*)bob_id);
    free((char*)alice_id);
    free(keyid_only.key_id);
    key_agreement_params_delete(params);
    free((uint8_t*)pck_rand);
    mikey_sakke_key_data_destroy(alice_pck);
}