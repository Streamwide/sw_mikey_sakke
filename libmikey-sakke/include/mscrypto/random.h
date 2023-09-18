#ifndef MSCRYPTO_RANDOM_H
#define MSCRYPTO_RANDOM_H

#include<functional>

namespace MikeySakkeCrypto
{
   /**
    * Signature for a function intended to fill an octet string with a
    * cryptographically strong random integer in the range [0, 2^8N)
    * where N is the number of octets in the string.
    */
   typedef std::function<void (uint8_t* octets, size_t N)> RandomGenerator;
}

#endif//MSCRYPTO_RANDOM_H

