#include "libmutil/Logger.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <sstream>
#include <util/octet-string.h>

// Developper note : since to generate I-Messages, we will mainly be using the C API, the unit test will be done using that same API

TEST(test_i_message, i_message_gmk) {
    mikey_sakke_set_log_level("debug");

    const char community[]     = "streamwide.com";
    uint8_t*   gmk             = mikey_sakke_gen_key();
    uint8_t*   gmk_id          = mikey_sakke_gen_key_id(GMK);
    const char kms_uri[]       = "0.0.0.0:8080";
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
    mikey_sakke_provision_key_material(gms_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(gms_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "SSK", "c9de2281bb7e7455cc63c95ebb0d576dbfd998b940d9eac71f3915689b83abec", true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "PVT", "049e8c279b4c673515032ac1e8d4ba5e91d3e38fbc9e96da577568cec7d46cbeb1edc62a9bc0bfbec07d832c8a771103d5f00717eadcaf6a420a9d1cdf82e726ec", false);
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
        mikey_sakke_set_public_parameter(gms_keys, community, "KeyPeriodNo", ss.str().c_str());
        mikey_sakke_set_public_parameter(gms_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(gms_keys, community, "SakkeSet", "1");
    }

    // Alice INIT
    const char alice_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* alice_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* alice_id = mikey_sakke_gen_user_id_format_2_for_period(alice_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(alice_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "SSK", "48bf63b2c12c2052181d7aed563926a1774591aa804a662e77ac6c2450e19c8a", true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "PVT", "04e71041fdee8964bd6e5ca83d495c440c3115ea0361da28814f3e097e0c16d83a7da45c972eded68a939390367bb4531e4ca18177912adcafe6b3d39b97494855", false);
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
        mikey_sakke_set_public_parameter(alice_keys, community, "KeyPeriodNo", ss.str().c_str());
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
    mikey_sakke_provision_key_material(bob_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(bob_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "SSK", "BD25489C01828D48D7C84A71C2B7F26D9032C1FD0CC426E65DF1AF92C79E30C2", true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "PVT", "04943539DC816FBD214BDAE6D6F16D1665F5B8307F320F4515BBA13A816F463711036E7C65340136C025673E0CC0C7EFF9C0C3D344C9C3FDC239C75978360D6BB3", false);
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
        mikey_sakke_set_public_parameter(bob_keys, community, "KeyPeriodNo", ss.str().c_str());
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
    uint8_t*   csk             = mikey_sakke_gen_key();
    uint8_t*   csk_id          = mikey_sakke_gen_key_id(CSK);
    uint8_t*   csk_rand        = mikey_sakke_gen_key();
    const char kms_uri[]       = "0.0.0.0:8080";
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
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "SSK", "c9de2281bb7e7455cc63c95ebb0d576dbfd998b940d9eac71f3915689b83abec", true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "PVT", "049e8c279b4c673515032ac1e8d4ba5e91d3e38fbc9e96da577568cec7d46cbeb1edc62a9bc0bfbec07d832c8a771103d5f00717eadcaf6a420a9d1cdf82e726ec", false);
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
        mikey_sakke_set_public_parameter(alice_keys, community, "KeyPeriodNo", ss.str().c_str());
        mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    }

    // GMS INIT
    const char gms_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* gms_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* gms_id = mikey_sakke_gen_user_id_format_2_for_period(gms_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(gms_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(gms_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(gms_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "SSK", "48bf63b2c12c2052181d7aed563926a1774591aa804a662e77ac6c2450e19c8a", true);
    mikey_sakke_provision_key_material(gms_keys, gms_id, "PVT", "04e71041fdee8964bd6e5ca83d495c440c3115ea0361da28814f3e097e0c16d83a7da45c972eded68a939390367bb4531e4ca18177912adcafe6b3d39b97494855", false);
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
        mikey_sakke_set_public_parameter(gms_keys, community, "KeyPeriodNo", ss.str().c_str());
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
    mikey_sakke_set_log_level("debug");

    const char community[]     = "streamwide.com";
    uint8_t*   pck             = mikey_sakke_gen_key();
    uint8_t*   pck_id          = mikey_sakke_gen_key_id(PCK);
    uint8_t*   pck_rand        = mikey_sakke_gen_key();
    const char kms_uri[]       = "0.0.0.0:8080";
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
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "SSK", "c9de2281bb7e7455cc63c95ebb0d576dbfd998b940d9eac71f3915689b83abec", true);
    mikey_sakke_provision_key_material(alice_keys, alice_id, "PVT", "049e8c279b4c673515032ac1e8d4ba5e91d3e38fbc9e96da577568cec7d46cbeb1edc62a9bc0bfbec07d832c8a771103d5f00717eadcaf6a420a9d1cdf82e726ec", false);
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
        mikey_sakke_set_public_parameter(alice_keys, community, "KeyPeriodNo", ss.str().c_str());
        mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
        mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    }

    // BOB INIT
    const char bob_uri[] = "alice@org.com";

    mikey_sakke_key_material_t* bob_keys = mikey_sakke_alloc_key_material("runtime:empty");
    const char* bob_id = mikey_sakke_gen_user_id_format_2_for_period(bob_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    mikey_sakke_add_community(bob_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(bob_keys, community, "KPAK", "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4", false);
    mikey_sakke_provision_key_material(bob_keys, community, "Z", "045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA4999258A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE", false);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "RSK", "04991dd025c1bbd553f8bb35e3fd730747116bfd5fce8d952a680a7ee33c81a9793fb109f2ea33804e8e248d56c436c903ccef65b96abae7e555bea4c6f6929ffc188f179f28dfd0fc0fac419871495bfa35cd7f7cb9a8c91a566ae4d359a0efafd53357618f87ce53cefa5a5906e53e8d0864140fb1ad9ee097214780b63aa1084e2da4b713ccd42ec7abf967dce69108a4d8ad173553080e8c5972cf9a9d00662b080fbbe4b13dfa46f1ee34e6fbc3eed7c47a9e7382c3f456bdb009f71305f0fb7e5fee32d0800707a5a1673271f1234f1c4d4fda52651ada3e292c519d998a9d2463e976df0c9f9c040f2716e2f51b7163b2f9986b176359a70467870c1f04", true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "SSK", "48bf63b2c12c2052181d7aed563926a1774591aa804a662e77ac6c2450e19c8a", true);
    mikey_sakke_provision_key_material(bob_keys, bob_id, "PVT", "04e71041fdee8964bd6e5ca83d495c440c3115ea0361da28814f3e097e0c16d83a7da45c972eded68a939390367bb4531e4ca18177912adcafe6b3d39b97494855", false);
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
        mikey_sakke_set_public_parameter(bob_keys, community, "KeyPeriodNo", ss.str().c_str());
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