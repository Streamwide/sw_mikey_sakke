#include "KMSResponseParser.h"
#include "libmutil/Logger.h"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

TEST(test_read_key, read_encoded_read_decoded) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    auto os = sw_kms_response_parser::readKeyToOctetString("3q2+7w==");
    ASSERT_STREQ("deadbeef", os.translate().c_str());

    auto os2 = sw_kms_response_parser::readKeyToOctetString("cafebabe4567");
    ASSERT_STREQ("cafebabe4567", os2.translate().c_str());

    auto os3 = sw_kms_response_parser::readKeyToOctetString("test_invalid");
    ASSERT_TRUE(os3.empty());
}

TEST(test_init_response_parse, secured_b64) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::filesystem::path filename = "./initResSecuredB64.xml";
    auto                  file     = std::ifstream(filename);
    std::stringstream     buffer;

    ASSERT_TRUE(file.is_open());

    buffer << file.rdbuf();

    auto resp = new sw_kms_response_parser::init_response_t();
    bool res  = sw_kms_response_parser::kmsInitParseResponse(buffer.str().c_str(), buffer.str().length(), resp, true);

    ASSERT_TRUE(res);
    delete resp;
}

TEST(test_init_response_parse, unsecured) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::filesystem::path filename = "initRes.xml";
    auto                  file     = std::ifstream(filename);
    std::stringstream     buffer;

    ASSERT_TRUE(file.is_open());

    buffer << file.rdbuf();

    auto resp = new sw_kms_response_parser::init_response_t();
    bool res  = sw_kms_response_parser::kmsInitParseResponse(buffer.str().c_str(), buffer.str().length(), resp, false);

    ASSERT_TRUE(res);
    delete resp;
}