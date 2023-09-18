#ifndef MIKEYPAYLOADSAKKE_H
#define MIKEYPAYLOADSAKKE_H

#include <libmikey/libmikey_config.h>

#include <libmikey/MikeyPayload.h>

#define MIKEYPAYLOAD_SAKKE_PAYLOAD_TYPE 26

// implemented in KeyAgreementSAKKE.cc
MikeyPayload* CreateIncomingPayloadSAKKE(uint8_t* payload, int limit);

#endif
