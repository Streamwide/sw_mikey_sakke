#include "KMSResponseParser.h"
#include "libmutil/Logger.h"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

TEST(test_keyprov_response_parse, secured_b64) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::filesystem::path filename = "keyProvResSecuredB64.xml";
    auto                  file     = std::ifstream(filename);
    std::stringstream     buffer;

    ASSERT_TRUE(file.is_open());

    buffer << file.rdbuf();

    auto resp = new sw_kms_response_parser::key_prov_response_t();
    bool res  = sw_kms_response_parser::kmsKeyProvParseResponse(buffer.str().c_str(), buffer.str().length(), resp, true);

    ASSERT_TRUE(res);
    delete resp;
}

TEST(test_keyprov_response_parse, unsecured) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::filesystem::path filename = "keyProvRes.xml";
    auto                  file     = std::ifstream(filename);
    std::stringstream     buffer;

    ASSERT_TRUE(file.is_open());

    buffer << file.rdbuf();

    auto resp = new sw_kms_response_parser::key_prov_response_t();
    bool res  = sw_kms_response_parser::kmsKeyProvParseResponse(buffer.str().c_str(), buffer.str().length(), resp, false);
    ASSERT_TRUE(res);

    ASSERT_EQ(resp->user_id.translate(), std::string("309d9c5b8e681c330283f85e04dab2ca4daa7dfd125f1d7bf9aa9f4e11fe91af"));
    ASSERT_EQ(resp->key_period_no, (uint32_t)631);

    std::string user_decrypt_key = resp->user_decrypt_key.translate();
    std::transform(user_decrypt_key.begin(), user_decrypt_key.end(), user_decrypt_key.begin(), ::toupper);
    ASSERT_EQ(user_decrypt_key,
              std::string("04488C2F01D0D3A9A0BB9D4ED398F23551B3A12D46D6F99D7AF94704171EAF600490EAFA45B0D6ADE7F502ABBEC8989FB6EFCD7E75BC58C2"
                          "CF35FBA3F44C447C031A7DD30F23444159C2578D4BC529BCA1D2B3B581233845D43FD19BE3F737BB8E26530E32CEC06EE9FF762EF7301885"
                          "2F6FBDD92847C563E20C9BA674AFC86D896B830B32B7E726447F84D272D50AF0DB95E9B8B2AEFCCE6DEA6030DEA3230C30C057B7C9A76AFC"
                          "6B95BF5E39A32C2576AD02079D87652B426B2E4872F3E6060E6CC16F1752F5728EFC4079392BA7E7AAF836DD5CBD50257F619D4F050022F6"
                          "2B848F95F463236A27743DFC894528C2CBB958B9B01B2AB53BCE04A09BA9139ECF"));

    std::string user_signing_key = resp->user_signing_key.translate();
    std::transform(user_signing_key.begin(), user_signing_key.end(), user_signing_key.begin(), ::toupper);
    ASSERT_EQ(user_signing_key, std::string("FA11BA4CE88B8B49539DC19FC1DC039EFD40E27AB96587DEE0D7A1D24ED82452"));

    std::string user_pub_token = resp->user_pub_token.translate();
    std::transform(user_pub_token.begin(), user_pub_token.end(), user_pub_token.begin(), ::toupper);
    ASSERT_EQ(user_pub_token, std::string("04076C72D43E0E9DD0786D222E23E26C74AA024D7C45405EF5B34F7D0C03E7C6D7B0BBA8031E8A"
                                          "D02A707B224605DC05517EE0792673B396EA02033B6F9701C6E1"));

    delete resp;
}