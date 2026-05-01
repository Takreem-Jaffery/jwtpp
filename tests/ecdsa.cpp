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

#include <gtest/gtest.h>
#include <openssl/err.h>

#include <jwtpp/jwtpp.hh>

// -----------------------------------------------------------------------
// TEST FILE NOTE — ecdsa tests
//
// The public interface of jwtpp::ecdsa is completely unchanged.
// The constructor, sign(), verify(), and gen() have identical signatures
// and semantics.
//
// Refactorings applied to ecdsa.cpp:
//   • Decompose Conditional — the inline degree-check error-message
//     construction inside gen() was moved to validate_curve_degree().
//   • Extract Method — the public-key derivation steps at the end of
//     gen() (point multiply, set public key, check key) were moved to
//     derive_and_set_public_key().
//
// Both helpers are file-static free functions, invisible to callers.
// No test code needs to change.
// -----------------------------------------------------------------------
 

TEST(jwtpp, sign_verify_ecdsa256) {
	jwtpp::claims cl;

	jwtpp::sp_ecdsa_key key;
	jwtpp::sp_ecdsa_key pubkey;

	EXPECT_NO_THROW(key = jwtpp::ecdsa::gen(NID_secp256k1));
	EXPECT_NO_THROW(pubkey = jwtpp::sp_ecdsa_key(EC_KEY_new(), ::EC_KEY_free));

	const EC_GROUP *group = EC_KEY_get0_group(key.get());
	const EC_POINT *p = EC_KEY_get0_public_key(key.get());

	EXPECT_EQ(EC_KEY_set_group(pubkey.get(), group), 1);
	EXPECT_TRUE(p != nullptr);
	EXPECT_EQ(EC_KEY_set_public_key(pubkey.get(), p), 1);

	jwtpp::sp_crypto e256;
	jwtpp::sp_crypto e384;
	jwtpp::sp_crypto e512;
	jwtpp::sp_crypto e256_pub;
	jwtpp::sp_crypto e384_pub;
	jwtpp::sp_crypto e512_pub;

	EXPECT_THROW(e256 = std::make_shared<jwtpp::ecdsa>(key, jwtpp::alg_t::RS256), std::exception);

	EXPECT_NO_THROW(e256 = std::make_shared<jwtpp::ecdsa>(key, jwtpp::alg_t::ES256));
	EXPECT_NO_THROW(e384 = std::make_shared<jwtpp::ecdsa>(key, jwtpp::alg_t::ES256));
	EXPECT_NO_THROW(e512 = std::make_shared<jwtpp::ecdsa>(key, jwtpp::alg_t::ES256));
	EXPECT_NO_THROW(e256_pub = std::make_shared<jwtpp::ecdsa>(pubkey, jwtpp::alg_t::ES256));
	EXPECT_NO_THROW(e384_pub = std::make_shared<jwtpp::ecdsa>(pubkey, jwtpp::alg_t::ES256));
	EXPECT_NO_THROW(e512_pub = std::make_shared<jwtpp::ecdsa>(pubkey, jwtpp::alg_t::ES256));

	std::string bearer = jwtpp::jws::sign_bearer(cl, e256);

	EXPECT_TRUE(!bearer.empty());

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(e256_pub));

	auto vf = [](jwtpp::sp_claims cl) {
		// The refactored claims checker only exposes the generic any() helper.
		return !cl->check().any("iss", "troian");
	};

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    EXPECT_TRUE(jws->verify(e256_pub, vf));
#else
	EXPECT_TRUE(jws->verify(e256_pub, vf));
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}
