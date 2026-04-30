// The MIT License (MIT)
//
// Copyright (c) 2016-2020 Artur Troian
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <openssl/hmac.h>

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

hmac::hmac(const secure_string &secret, alg_t a)
	: crypto(a)
	, _secret(secret)
{
	if (a != alg_t::HS256 && a != alg_t::HS384 && a != alg_t::HS512) {
		throw std::invalid_argument("Invalid algorithm");
	}

	if (secret.empty()) {
		throw std::invalid_argument("Invalid secret");
	}
}

// [Extract Method]
// The switch on _alg to select an EVP_MD* was inlined inside sign(), mixing
// algorithm selection with the hashing logic. Extracted into select_evp() so
// sign() reads as a sequence of clearly named steps.
const EVP_MD *hmac::select_evp() const {
	switch (_alg) {
	case alg_t::HS256: return EVP_sha256();
	case alg_t::HS384: return EVP_sha384();
	case alg_t::HS512: return EVP_sha512();
	default:
		throw std::runtime_error("Invalid alg");
	}
}

// [Extract Method]
// The #if OPENSSL_VERSION_NUMBER guards for allocating HMAC_CTX were
// scattered through sign(), polluting the business logic with version
// compatibility concerns. Centralised here so sign() never sees them.
HMAC_CTX *hmac::create_hmac_ctx() const {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX *ctx = new HMAC_CTX();
	HMAC_CTX_init(ctx);
	return ctx;
#else
	return HMAC_CTX_new();
#endif
}

// [Extract Method]
// Matching cleanup extracted for the same reason as create_hmac_ctx().
void hmac::destroy_hmac_ctx(HMAC_CTX *ctx) const {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_cleanup(ctx);
	delete ctx;
#else
	HMAC_CTX_free(ctx);
#endif
}

// [Extract Method]
// The raw HMAC computation (init → update → final) is extracted into
// compute_hmac() so sign() is reduced to three named steps:
// select digest, compute MAC, encode result.
std::vector<uint8_t> hmac::compute_hmac(const std::string &data, const EVP_MD *evp) const {
	HMAC_CTX *ctx = create_hmac_ctx();

	HMAC_Init_ex(ctx, _secret.data(), static_cast<int>(_secret.length()), evp, nullptr);
	HMAC_Update(ctx, reinterpret_cast<const uint8_t *>(data.c_str()), data.size());

	// [Replace Temp with Query]
	// `size` was a mutable temp populated by HMAC_Final then immediately used.
	// Replaced by sizing the vector from EVP_MD_size() upfront and letting
	// HMAC_Final write the actual byte count back into a local.
	std::vector<uint8_t> result(static_cast<size_t>(EVP_MD_size(evp)));
	uint32_t written = 0;
	HMAC_Final(ctx, result.data(), &written);
	result.resize(written);

	destroy_hmac_ctx(ctx);
	return result;
}

std::string hmac::sign(const std::string &data) {
	if (data.empty()) {
		throw std::invalid_argument("data is empty");
	}

	const EVP_MD *evp = select_evp();
	std::vector<uint8_t> mac = compute_hmac(data, evp);

	return b64::encode_uri(mac.data(), static_cast<uint32_t>(mac.size()));

}

bool hmac::verify(const std::string &data, const std::string &sig) {
	return sig == sign(data);
}

} // namespace jwtpp
