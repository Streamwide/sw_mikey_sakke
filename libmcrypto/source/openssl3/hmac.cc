/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 */

#include <config.h>

#include <libmcrypto/hmac.h>
#include <openssl/hmac.h>

void hmac_sha1(const uint8_t* key, unsigned int key_length, const unsigned char* data, unsigned int data_length, unsigned char* mac,
               unsigned int* mac_length) {
    HMAC(EVP_sha1(), key, key_length, data, data_length, mac, mac_length);
}

void hmac_sha1(const unsigned char* key, unsigned int key_length, unsigned char* data_chunks[], unsigned int data_chunck_length[],
               unsigned char* mac, unsigned int* mac_length) {
    mac = EVP_Q_mac(nullptr, "SHA1", nullptr, nullptr, nullptr, key, key_length, *data_chunks, *data_chunck_length, nullptr, 0,
                    (size_t*)mac_length);
    (void)mac;
}

void hmac_sha256(const uint8_t* key, unsigned int key_length, const unsigned char* data, unsigned int data_length, unsigned char* mac,
                 unsigned int* mac_length) {
    HMAC(EVP_sha256(), key, key_length, data, data_length, mac, mac_length);
}

void hmac_sha256(const unsigned char* key, unsigned int key_length, unsigned char* data_chunks[], unsigned int data_chunck_length[],
                 unsigned char* mac, unsigned int* mac_length) {
    mac = EVP_Q_mac(nullptr, "SHA256", nullptr, nullptr, nullptr, key, key_length, *data_chunks, *data_chunck_length, nullptr, 0,
                    (size_t*)mac_length);
    (void)mac;
}
