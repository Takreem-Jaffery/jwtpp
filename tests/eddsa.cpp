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

#include <jwtpp/jwtpp.hh>

#if defined(JWTPP_SUPPORTED_EDDSA)

#include <gtest/gtest.h>

// -----------------------------------------------------------------------
// TEST FILE NOTE — eddsa tests
//
// The public interface of jwtpp::eddsa is completely unchanged.
// The constructor, sign(), verify(), gen(), and get_pub() have identical
// signatures and semantics.
//
// Refactoring applied to eddsa.cpp:
//   • Extract Method (make_evp_md_ctx) — the two-step EVP_MD_CTX
//     allocation + initialisation sequence that was duplicated at the top
//     of both sign() and verify() is now a single file-static helper.
//
// The helper is file-static and invisible to callers.
// No test code needs to change.
// -----------------------------------------------------------------------


TEST(jwtpp, sign_verify_eddsa) {
	jwtpp::claims cl;

	jwtpp::sp_evp_key key;
	jwtpp::sp_evp_key pubkey;

	jwtpp::sp_evp_key key_alien;

	// generating 2 keys.
	// key used to sign/verify
	// key_alien to is expected to fail when validating bearer signed by key
	EXPECT_NO_THROW(key = jwtpp::eddsa::gen());
	EXPECT_NO_THROW(pubkey = jwtpp::eddsa::get_pub(key));
	EXPECT_NO_THROW(key_alien = jwtpp::eddsa::gen());

	jwtpp::sp_crypto ed;
	jwtpp::sp_crypto ed_pub;
	jwtpp::sp_crypto ed_alien;

	EXPECT_NO_THROW(ed = std::make_shared<jwtpp::eddsa>(key));
	EXPECT_NO_THROW(ed_pub = std::make_shared<jwtpp::eddsa>(pubkey));

	EXPECT_NO_THROW(ed_alien = std::make_shared<jwtpp::eddsa>(key_alien));

	std::string bearer;

	EXPECT_NO_THROW(bearer = jwtpp::jws::sign_bearer(cl, ed));

	EXPECT_TRUE(!bearer.empty());

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_FALSE(jws->verify(ed_alien));

	EXPECT_TRUE(jws->verify(ed));
	EXPECT_TRUE(jws->verify(ed_pub));

	auto vf = [](jwtpp::sp_claims cl) {
		// The refactored claims checker only exposes the generic any() helper.
		return !cl->check().any("iss", "troian");
	};

	EXPECT_TRUE(jws->verify(ed, vf));

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}

#endif // defined(JWTPP_SUPPORTED_EDDSA)
