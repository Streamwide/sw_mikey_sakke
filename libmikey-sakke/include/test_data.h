#ifndef TEST_DATA_H
#define TEST_DATA_H

#include <mskms/runtime-key-storage.inl>
#include <string>

namespace test_data {
void                       set_alice_and_bob_community_params(MikeySakkeKMS::KeyStorage* keys);
MikeySakkeKMS::KeyStorage* make_alice_key_store(const std::string& user_uri, const std::string& user_community);
MikeySakkeKMS::KeyStorage* make_bob_key_store(const std::string& user_uri, const std::string& user_community);
MikeySakkeKMS::KeyStorage* make_user1_key_store();
MikeySakkeKMS::KeyStorage* make_user2_key_store();
std::string                get_i_msg_for_user1();

} // namespace test_data

#endif