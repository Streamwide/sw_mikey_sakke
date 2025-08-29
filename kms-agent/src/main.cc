#include "KMClient.h"
#include <libmutil/Logger.h>
#ifdef USE_SPDLOG
#include <spdlog/spdlog.h>
#endif // USE_SPDLOG
#include <test_data.h>

int main() {
#ifdef USE_SPDLOG
    spdlog::set_level(spdlog::level::from_str("debug"));
#endif // USE_SPDLOG
    auto client = KMClient("http://192.168.4.101", false, nullptr, nullptr, 1500, test_data::get_xoauth2_token());
    client.setUserUri("user1@streamwide.com");
    client.sendRequest(request_type_e::INIT, nullptr);
    client.sendRequest(request_type_e::KEY_PROV, nullptr);
    return 0;
}