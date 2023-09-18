#ifndef MSKMS_CLIENT_FWD_H
#define MSKMS_CLIENT_FWD_H

namespace MikeySakkeKMS {
class KeyStorage;
class Client;
// class AutonomousClient;
typedef Client                            AutonomousClient; // XXX
typedef std::shared_ptr<KeyStorage>       KeyStoragePtr;
typedef std::shared_ptr<const KeyStorage> KeyAccessPtr;
typedef std::shared_ptr<Client>           ClientPtr;
typedef std::shared_ptr<AutonomousClient> AutonomousClientPtr;
} // namespace MikeySakkeKMS

#endif // MSKMS_CLIENT_FWD_H
