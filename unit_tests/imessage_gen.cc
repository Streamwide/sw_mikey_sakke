#include "libmutil/Logger.h"
#include "mikeysakke4c.h"
#include "util/octet-string.h"
#include "gtest/gtest.h"

TEST(imessage_gen, csk) {
    mikey_sakke_set_log_level("warning");
    MIKEY_SAKKE_LOGW("Request keys associated with alice@org.com and generate a CSK I-Message for gms@streamwide.com");
    mikey_sakke_key_material_t* keys         = mikey_sakke_alloc_key_material("runtime:empty");
    km_client_t*                alice_client = mikey_sakke_client_create("127.0.0.1", false, keys, 1500);
    const char                  alice_uri[]  = "alice@org.com";
    mikey_sakke_user_t*         alice_user   = mikey_sakke_alloc_user(alice_uri, keys);

    mikey_sakke_add_community(keys, "streamwide.com");
    mikey_sakke_client_set_user_uri(alice_client, "alice@org.com");
    // Use a token generated with uri = alice@org.com
    mikey_sakke_client_set_token(
        alice_client, "eyJhbGciOiJSUzI1NiJ9."
                      "eyJtY3B0dF9pZCI6ImFsaWNlQG9yZy5jb20iLCJleHAiOjE2OTAwMDAwMDAsInNjb3BlIjpbIm9wZW5pZCIsIjNncHA6bWNwdHQ6cHR0X3NlcnZlciJd"
                      "LCJjbGllbnRfaWQiOiJtY3B0dF9jbGllbnQifQ.ihSsf95oOTg8or0Z8XixghOuyIRRhCcddNazcAT5uxo5N9ZRvyPi2cd_"
                      "81GIeupfTXiMvllPsoJ7BcQfu3T79aADcFYHxv8t989ZpWHyxZpiVbrdJRxGy7iaq08Jh52Sp6BrTOZAypuPWas8kT7bPWK4_"
                      "E78bj9PmrogWwOsiBCAPO8roNo7HqOkRGRZGKtHPpjX_mRJcNH8VTkritV2-SBL9gI_7dNly-SGHyFljGRDROTlT210QOI8KkzGQJJ-"
                      "GrN59fNYEGh3AgZs_6Btoh4FxNEMHHqpPzdXimaNIszaoMiuo9EqY9F8WhNVrDUoIpPn1ftp2LZ5pZ964tbsew");
    ASSERT_EQ(mikey_sakke_fetch_key_material_init(alice_client), 0);
    struct kms_key_material_init* init_keys = mikey_sakke_get_key_material_init(alice_client);

    ASSERT_EQ(mikey_sakke_fetch_key_material_key_prov(alice_client), 0);
    struct kms_key_material_key_prov* keyprov_keys = mikey_sakke_get_key_material_key_prov(alice_client);

    const char* alice_id = mikey_sakke_gen_user_id_format_2(init_keys->resp->user_uri, init_keys->resp->kms_uri, init_keys->user_key_period,
                                                            init_keys->user_key_offset);
    ASSERT_STREQ(alice_id, keyprov_keys->user_id);
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(alice_id, keys));

    // Generate I_MESSAGE from Alice to GMS
    uint8_t*            csk            = mikey_sakke_gen_key(16);
    uint8_t*            csk_rand       = mikey_sakke_gen_key(16);
    uint8_t*            csk_id         = mikey_sakke_gen_key_id(CSK);
    mikey_sakke_call_t* alice_outgoing = mikey_sakke_alloc_call(alice_user);

    auto csk_os      = OctetString {16, csk};
    auto csk_rand_os = OctetString {16, csk_rand};
    auto csk_id_os   = OctetString {4, csk_id};
    MIKEY_SAKKE_LOGW("Generating I-Message with:");
    MIKEY_SAKKE_LOGW("CSK       = %s", csk_os.translate().c_str());
    MIKEY_SAKKE_LOGW("CSK-ID    = %s", csk_id_os.translate().c_str());
    MIKEY_SAKKE_LOGW("CSK-RAND  = %s", csk_rand_os.translate().c_str());

    mikey_sakke_add_sender_stream(alice_outgoing, 0xcafebabe);

    struct key_agreement_params*             params   = key_agreement_params_create(CSK, 16, csk, 4, csk_id, 16, csk_rand);
    [[maybe_unused]] mikey_key_mgmt_string_t init_gms = mikey_sakke_group_init(alice_outgoing, "gms@streamwide.com", params);

    MIKEY_SAKKE_LOGW("Generated CSK I-Message : %s", init_gms.ptr);

    // Cleanup
    mikey_sakke_free_key_mgmt_string(init_gms);
    key_agreement_params_delete(params);
    mikey_sakke_free_call(alice_outgoing);
    free(csk_id);
    free(csk);
    free(csk_rand);
    free((char*)alice_id);
    kms_key_material_key_prov_destroy(keyprov_keys);
    kms_key_material_init_destroy(init_keys);
    mikey_sakke_free_user(alice_user);
    mikey_sakke_client_destroy(alice_client);
    mikey_sakke_free_key_material(keys);
}
