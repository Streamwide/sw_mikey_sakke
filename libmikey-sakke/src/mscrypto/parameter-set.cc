#include <mscrypto/parameter-set.h>
#include <util/bigint-ssl.h>

namespace MikeySakkeCrypto {

// RFC 6509
SakkeParameterSet const& sakke_param_set_1() {
    static SakkeParameterSet params(
        /*
         * As of 01-Apr-2021 there is really but one Sakke Parameter Set to use
         * Sakke Payload defined in https://tools.ietf.org/html/rfc6509#section-4.2
         * Sakke Parameter Set Provided here https://tools.ietf.org/html/rfc6509#appendix-A
         */

        /*iana*/ 1,

        /* n  */ 128,

        /* p  */
        "997ABB1F 0A563FDA 65C61198 DAD0657A"
        "416C0CE1 9CB48261 BE9AE358 B3E01A2E"
        "F40AAB27 E2FC0F1B 228730D5 31A59CB0"
        "E791B39F F7C88A19 356D27F4 A666A6D0"
        "E26C6487 326B4CD4 512AC5CD 65681CE1"
        "B6AFF4A8 31852A82 A7CF3C52 1C3C09AA"
        "9F94D6AF 56971F1F FCE3E823 89857DB0"
        "80C5DF10 AC7ACE87 666D807A FEA85FEB",

        /* q  */
        "265EAEC7 C2958FF6 99718466 36B4195E"
        "905B0338 672D2098 6FA6B8D6 2CF8068B"
        "BD02AAC9 F8BF03C6 C8A1CC35 4C69672C"
        "39E46CE7 FDF22286 4D5B49FD 2999A9B4"
        "389B1921 CC9AD335 144AB173 595A0738"
        "6DABFD2A 0C614AA0 A9F3CF14 870F026A"
        "A7E535AB D5A5C7C7 FF38FA08 E2615F6C"
        "203177C4 2B1EB3A1 D99B601E BFAA17FB",

        /* Px */
        "53FC09EE 332C29AD 0A799005 3ED9B52A"
        "2B1A2FD6 0AEC69C6 98B2F204 B6FF7CBF"
        "B5EDB6C0 F6CE2308 AB10DB90 30B09E10"
        "43D5F22C DB9DFA55 718BD9E7 406CE890"
        "9760AF76 5DD5BCCB 337C8654 8B72F2E1"
        "A702C339 7A60DE74 A7C1514D BA66910D"
        "D5CFB4CC 80728D87 EE9163A5 B63F73EC"
        "80EC46C4 967E0979 880DC8AB EAE63895",

        /* Py */
        "0A824906 3F6009F1 F9F1F053 3634A135"
        "D3E82016 02990696 3D778D82 1E141178"
        "F5EA69F4 654EC2B9 E7F7F5E5 F0DE55F6"
        "6B598CCF 9A140B2E 416CFF0C A9E032B9"
        "70DAE117 AD547C6C CAD696B5 B7652FE0"
        "AC6F1E80 164AA989 492D979F C5A4D5F2"
        "13515AD7 E9CB99A9 80BDAD5A D5BB4636"
        "ADB9B570 6A67DCDE 75573FD7 1BEF16D7",

        /* g  */
        "66FC2A43 2B6EA392 148F1586 7D623068"
        "C6A87BD1 FB94C41E 27FABE65 8E015A87"
        "371E9474 4C96FEDA 449AE956 3F8BC446"
        "CBFDA85D 5D00EF57 7072DA8F 541721BE"
        "EE0FAED1 828EAB90 B99DFB01 38C78433"
        "55DF0460 B4A9FD74 B4F1A32B CAFA1FFA"
        "D682C033 A7942BCC E3720F20 B9B7B040"
        "3C8CAE87 B7A0042A CDE0FAB3 6461EA46",

        /* hash     */ SHA256,
        /* hash_len */ HashLen<SHA256>::octets);
    return params;
}

// non-RFC 6509
SakkeParameterSet const& sakke_param_set_2() {
    static SakkeParameterSet params(
        /* WARNING: Params are exactly same as "sakke_param_set_1()" BUT
        the "n" field is set to 256 in order to handle 256bit key during
        ciphering & unciphering process. This change is not present in
        any spec, so there is a chance for non-compatibility.
        -> Even though RFC-6508 S2.1 states "n: the size of symmetric keys
        in bits to be exchanged by SAKKE"
         */

        /*iana*/ 1,

        /* n  */ 256,

        /* p  */
        "997ABB1F 0A563FDA 65C61198 DAD0657A"
        "416C0CE1 9CB48261 BE9AE358 B3E01A2E"
        "F40AAB27 E2FC0F1B 228730D5 31A59CB0"
        "E791B39F F7C88A19 356D27F4 A666A6D0"
        "E26C6487 326B4CD4 512AC5CD 65681CE1"
        "B6AFF4A8 31852A82 A7CF3C52 1C3C09AA"
        "9F94D6AF 56971F1F FCE3E823 89857DB0"
        "80C5DF10 AC7ACE87 666D807A FEA85FEB",

        /* q  */
        "265EAEC7 C2958FF6 99718466 36B4195E"
        "905B0338 672D2098 6FA6B8D6 2CF8068B"
        "BD02AAC9 F8BF03C6 C8A1CC35 4C69672C"
        "39E46CE7 FDF22286 4D5B49FD 2999A9B4"
        "389B1921 CC9AD335 144AB173 595A0738"
        "6DABFD2A 0C614AA0 A9F3CF14 870F026A"
        "A7E535AB D5A5C7C7 FF38FA08 E2615F6C"
        "203177C4 2B1EB3A1 D99B601E BFAA17FB",

        /* Px */
        "53FC09EE 332C29AD 0A799005 3ED9B52A"
        "2B1A2FD6 0AEC69C6 98B2F204 B6FF7CBF"
        "B5EDB6C0 F6CE2308 AB10DB90 30B09E10"
        "43D5F22C DB9DFA55 718BD9E7 406CE890"
        "9760AF76 5DD5BCCB 337C8654 8B72F2E1"
        "A702C339 7A60DE74 A7C1514D BA66910D"
        "D5CFB4CC 80728D87 EE9163A5 B63F73EC"
        "80EC46C4 967E0979 880DC8AB EAE63895",

        /* Py */
        "0A824906 3F6009F1 F9F1F053 3634A135"
        "D3E82016 02990696 3D778D82 1E141178"
        "F5EA69F4 654EC2B9 E7F7F5E5 F0DE55F6"
        "6B598CCF 9A140B2E 416CFF0C A9E032B9"
        "70DAE117 AD547C6C CAD696B5 B7652FE0"
        "AC6F1E80 164AA989 492D979F C5A4D5F2"
        "13515AD7 E9CB99A9 80BDAD5A D5BB4636"
        "ADB9B570 6A67DCDE 75573FD7 1BEF16D7",

        /* g  */
        "66FC2A43 2B6EA392 148F1586 7D623068"
        "C6A87BD1 FB94C41E 27FABE65 8E015A87"
        "371E9474 4C96FEDA 449AE956 3F8BC446"
        "CBFDA85D 5D00EF57 7072DA8F 541721BE"
        "EE0FAED1 828EAB90 B99DFB01 38C78433"
        "55DF0460 B4A9FD74 B4F1A32B CAFA1FFA"
        "D682C033 A7942BCC E3720F20 B9B7B040"
        "3C8CAE87 B7A0042A CDE0FAB3 6461EA46",

        /* hash     */ SHA256,
        /* hash_len */ HashLen<SHA256>::octets);
    return params;
}

SigningParameterSet const& eccsi_6509_param_set() {
    static SigningParameterSet params(
        /* nist     */ "P-256",
        /* hash     */ SHA256,
        /* hash_len */ HashLen<SHA256>::octets);
    return params;
}

SigningParameterSet::SigningParameterSet(std::string const& nist, HashingAlgorithm hash, int hash_len)
    : curve(new ECC::PrimeCurveJacobian(nist)), hash(hash), hash_len(hash_len) {}

SakkeParameterSet::SakkeParameterSet(uint8_t iana_sakke_params_value, int n, char const* p, char const* q, char const* Px, char const* Py,
                                     char const* g, HashingAlgorithm hash, int hash_len)
    : iana_sakke_params_value(iana_sakke_params_value), n(n),
      E_a(new ECC::PrimeCurveAffine(bigint(p, 16), -3, 1, 0, bigint(q, 16), bigint(Px, 16), bigint(Py, 16))),
      E_j(new ECC::PrimeCurveJacobian(bigint_ssl(p, 16), -3l, 1ul, 0ul, bigint_ssl(q, 16), bigint_ssl(Px, 16), bigint_ssl(Py, 16))),
      g(g, 16), hash(hash), hash_len(hash_len) {}

} // namespace MikeySakkeCrypto
