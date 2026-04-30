//
// Created by Artur Troian on 2019-08-14
//

#include <iostream>
#include <jwtpp/jwtpp.hh>

namespace jwtpp {

namespace {

//Extract Method
//The algorithm validation guard was inlined at the top of the constructor.
//Extracted to a named function so the constructor reads as a pure sequence of invariant checks, and the rule is reusable (e.g. in a factory).
void validate_pss_alg(alg_t a) {
    if (a != alg_t::PS256 && a != alg_t::PS384 && a != alg_t::PS512) {
        throw std::invalid_argument("Invalid algorithm: PSS requires PS256, PS384, or PS512");
    }
}

//Extract Method
//Key-size adequacy was a magic-number check buried in the constructor.
//Naming it documents *why* 256 bytes (= 2048-bit key) is the PS512 minimum.
void validate_key_size_for_alg(alg_t a, size_t key_size) {
    constexpr size_t PS512_MIN_KEY_BYTES = 256; // 2048-bit RSA minimum
    if (a == alg_t::PS512 && key_size < PS512_MIN_KEY_BYTES) {
        throw std::runtime_error("PS512 requires at least a 2048-bit RSA key");
    }
}

} //anonymous namespace

//Replace Constructor with Factory Method
//The constructor is retained (it is small and well-bounded now), but a static factory `pss::create()` is provided as the preferred construction path.
//This keeps the constructor honest (no business logic) while giving callers a descriptive entry point that signals intent.

//static
std::shared_ptr<pss> pss::create(sp_rsa_key key, alg_t a) {
    return std::make_shared<pss>(key, a);
}

pss::pss(sp_rsa_key key, alg_t a)
    : crypto(a)
    , _r(key)
{
    //Decompose Conditional
    //Two independent invariants are now each one named call instead of a compound if-expression with a magic constant.
    validate_pss_alg(a);
    _key_size = static_cast<size_t>(RSA_size(_r.get()));
    validate_key_size_for_alg(a, _key_size);
}

std::string pss::sign(const std::string &data) {
    if (data.empty()) {
        throw std::invalid_argument("data is empty");
    }

    digest d(_hash_type,
             reinterpret_cast<const uint8_t *>(data.data()),
             data.length());

    //Replace Temp with Query
    //`padded` and `sig` are still named (they are non-trivial managed buffers)
    //but their construction is consolidated into the narrowest possible scope.
    auto padded = std::shared_ptr<uint8_t>(new uint8_t[_key_size],
                                           std::default_delete<uint8_t[]>());
    auto sig    = std::shared_ptr<uint8_t>(new uint8_t[_key_size],
                                           std::default_delete<uint8_t[]>());

    if (RSA_padding_add_PKCS1_PSS(
            _r.get(), padded.get(), d.data(), digest::md(_hash_type), -1) != 1) {
        throw std::runtime_error("failed to create PSS padding");
    }

    if (RSA_private_encrypt(
            static_cast<int>(_key_size),
            padded.get(), sig.get(), _r.get(), RSA_NO_PADDING) < 0) {
        throw std::runtime_error("RSA private encrypt failed");
    }

    return b64::encode_uri(sig.get(), _key_size);
}

bool pss::verify(const std::string &data, const std::string &sig) {
    digest d(_hash_type,
             reinterpret_cast<const uint8_t *>(data.data()),
             data.length());

    //Replace Temp with Query
    //`decoded_sig` result is used immediately; the buffer name makes the decode step explicit without an intermediate variable for its size.
    auto decrypted_sig = std::shared_ptr<uint8_t>(new uint8_t[_key_size],
                                                  std::default_delete<uint8_t[]>());
    const auto decoded_sig = b64::decode_uri(sig.data(), sig.length());

    if (RSA_public_decrypt(
            static_cast<int>(decoded_sig.size()),
            decoded_sig.data(), decrypted_sig.get(),
            _r.get(), RSA_NO_PADDING) < 0) {
        throw std::runtime_error("RSA public decrypt failed: invalid signature");
    }

    return RSA_verify_PKCS1_PSS(
               _r.get(), d.data(), digest::md(_hash_type),
               decrypted_sig.get(), -1) == 1;
}

} // namespace jwtpp