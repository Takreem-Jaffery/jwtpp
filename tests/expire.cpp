  
// The MIT License (MIT)
//
// Copyright (c) 2020 ihmc3jn09hk
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

#include <jwtpp/jwtpp.hh>
#include <chrono>

TEST(jwtpp, check_expire) {
	// REFACTORING: Replace temporary variable with query
	// The intermediate variable 'future_t' was inlined directly into to_time_t() call,
	// eliminating unnecessary temporary and making intent clearer.
	auto future = std::chrono::system_clock::to_time_t(
		std::chrono::system_clock::now() + std::chrono::seconds{30}
	);

	jwtpp::claims cl;

	// The claims API exposes generic accessors here, so we store and read
	// the expiration value through any() rather than removed convenience helpers.
	cl.set().any("exp", std::to_string(future));
  
	jwtpp::sp_rsa_key key;
	jwtpp::sp_rsa_key pubkey;

	jwtpp::sp_crypto r512;
	jwtpp::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jwtpp::rsa::gen(4096));
	EXPECT_NO_THROW(pubkey = jwtpp::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));

	EXPECT_NO_THROW(r512 = std::make_shared<jwtpp::rsa>(key, jwtpp::alg_t::RS512));
	EXPECT_NO_THROW(r512_pub = std::make_shared<jwtpp::rsa>(pubkey, jwtpp::alg_t::RS512));

	std::string bearer = jwtpp::jws::sign_bearer(cl, r512);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));
  
	// REFACTORING: Replace temporary variable with query
	// The intermediate variable 'now_t' was inlined directly into to_time_t() call,
	// eliminating unnecessary temporary.
	auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	// REFACTORING: Extract method
	// The repeated time verification logic from two nearly-identical lambdas
	// has been consolidated into a single helper lambda that takes a comparison operator.
	auto verify_expiry = [&now](jwtpp::sp_claims cl, 
		bool (*compare)(double)) -> bool {
		// Read the expiration claim through the generic getter to match the
		// refactored claims interface.
		time_t future_s = std::stoll(cl->get().any("exp"));
		return compare(difftime(future_s, now));
	};

	auto vf = [&verify_expiry](jwtpp::sp_claims cl) {
		return verify_expiry(cl, [](double d) { return 0 < d; });
	};

	EXPECT_TRUE(jws->verify(r512_pub, vf));

	auto vf_ = [&verify_expiry](jwtpp::sp_claims cl) {
		return verify_expiry(cl, [](double d) { return 0 > -d; });
	};

	EXPECT_TRUE(jws->verify(r512_pub, vf_));
}
