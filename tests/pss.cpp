// The MIT License (MIT)
//
// Copyright (c) 2016-2020 Artur Troian
// ...

#include <gtest/gtest.h>
#include <jwtpp/jwtpp.hh>

//Extract Class / Pull Up Field 
//The three sign_verify tests each repeated the same ~10-line setup block:
//generate an RSA key, duplicate the public key, create all six crypto objects.
//That setup is pulled up into a typed GTest fixture. The per-variant differences (key size, which alg to sign with, which alg combos to reject) are expressed as parameters, not copy-pasted code.
//This also applies "Replace Temp with Query": the local `key`, `pubkey`,
//rXXX / rXXX_pub variables are all members now, named once.

class PssSignVerifyFixture : public ::testing::TestWithParam<
    std::tuple<int /*key_bits*/, jwtpp::alg_t /*sign_alg*/>>
{
protected:
    jwtpp::sp_rsa_key  key;
    jwtpp::sp_rsa_key  pubkey;
    jwtpp::sp_crypto   signer;
    jwtpp::sp_crypto   verifier;

    //Extract Method
    //SetUp() replaces the repeated boilerplate in every test body.
    void SetUp() override {
        const auto [key_bits, sign_alg] = GetParam();

        ASSERT_NO_THROW(key    = jwtpp::rsa::gen(key_bits));
        ASSERT_NO_THROW(pubkey = jwtpp::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
        ASSERT_NO_THROW(signer   = jwtpp::pss::create(key,    sign_alg));
        ASSERT_NO_THROW(verifier = jwtpp::pss::create(pubkey, sign_alg));
    }

    //Extract Method
    //The "invalid bearer" edge-case block was copy-pasted verbatim in all three original tests. One helper eliminates that duplication.
    void expect_invalid_bearers_throw() {
        jwtpp::sp_jws jws;
        EXPECT_THROW(jws = jwtpp::jws::parse("ghdfgddf"),         std::exception);
        EXPECT_THROW(jws = jwtpp::jws::parse("Bearer "),          std::exception);
        EXPECT_THROW(jws = jwtpp::jws::parse("Bearer bla.bla.bla"), std::exception);
    }
};

//Form Template Method
//The body of every sign/verify test follows the same template:
//   1. Sign a bearer with `signer`
//   2. Parse it
//   3. Verify with `verifier` (public key, same alg) 
//   4. Verify with a custom callback                
//   5. Verify with a wrong-alg crypto                
//   6. Exercise invalid bearer inputs                
//
//The template is expressed as a single parameterised test body.

TEST_P(PssSignVerifyFixture, sign_and_verify) {
    jwtpp::claims cl;
    const std::string bearer = jwtpp::jws::sign_bearer(cl, signer);

    jwtpp::sp_jws jws;
    ASSERT_NO_THROW(jws = jwtpp::jws::parse(bearer));

    //Verify with full private-key crypto and with public-key-only crypto.
    EXPECT_TRUE(jws->verify(signer));
    EXPECT_TRUE(jws->verify(verifier));

    //Custom callback: accepts tokens not issued by "troian".
    auto accept_cb = [](jwtpp::sp_claims c) {
        return !c->check().iss("troian");
    };
    EXPECT_TRUE(jws->verify(verifier, accept_cb));

    //Verifying with a crypto object of a *different* alg must throw.
    //I grabbed the alg from the fixture parameter and picked the other one.
    const auto [key_bits, sign_alg] = GetParam();
    const jwtpp::alg_t wrong_alg =
        (sign_alg == jwtpp::alg_t::PS256) ? jwtpp::alg_t::PS384 : jwtpp::alg_t::PS256;

    //Only attempt the wrong-alg verifier if the key is big enough for it.
    jwtpp::sp_crypto wrong_verifier;
    if (wrong_alg != jwtpp::alg_t::PS512 || key_bits >= 2048) {
        ASSERT_NO_THROW(wrong_verifier = jwtpp::pss::create(pubkey, wrong_alg));
        EXPECT_THROW(jws->verify(wrong_verifier, accept_cb), std::exception);
    }

    expect_invalid_bearers_throw();
}

//Parameterize (Replace Type Code with State/Strategy) 
//Instead of three near-identical test functions distinguished only by
//{key_bits, alg}, we declare the varying parameters explicitly.
//Adding PS512-2048 no longer requires copy-pasting a new test function.

INSTANTIATE_TEST_SUITE_P(
    PssVariants,
    PssSignVerifyFixture,
    ::testing::Values(
        std::make_tuple(1024, jwtpp::alg_t::PS256),
        std::make_tuple(1024, jwtpp::alg_t::PS384),
        std::make_tuple(2048, jwtpp::alg_t::PS512)
    ),
    [](const ::testing::TestParamInfo<PssSignVerifyFixture::ParamType> &info) {
        //Human-readable test name in output, e.g. "PS256_1024bit"
        const auto [bits, alg] = info.param;
        return jwtpp::crypto::alg2str(alg) + "_" + std::to_string(bits) + "bit";
    }
);

//Extract Method (constructor validation tests kept separate)
//These do not follow the sign/verify template so they stay as plain tests, but the key-generation noise is eliminated with a simple local helper.

namespace {
jwtpp::sp_rsa_key make_key(int bits) {
    jwtpp::sp_rsa_key k;
    EXPECT_NO_THROW(k = jwtpp::rsa::gen(bits));
    return k;
}
} //anonymous namespace

TEST(jwtpp, pss_construction_valid_algs) {
    auto key = make_key(1024);
    EXPECT_NO_THROW(jwtpp::pss::create(key, jwtpp::alg_t::PS256));
    EXPECT_NO_THROW(jwtpp::pss::create(key, jwtpp::alg_t::PS384));
}

TEST(jwtpp, pss_construction_ps512_requires_2048bit_key) {
    auto small_key = make_key(1024);
    EXPECT_THROW(jwtpp::pss::create(small_key, jwtpp::alg_t::PS512), std::exception);

    auto large_key = make_key(2048);
    EXPECT_NO_THROW(jwtpp::pss::create(large_key, jwtpp::alg_t::PS512));
}

TEST(jwtpp, pss_construction_rejects_non_pss_algs) {
    auto key = make_key(1024);
    EXPECT_THROW(jwtpp::pss::create(key, jwtpp::alg_t::HS256), std::exception);
    EXPECT_THROW(jwtpp::pss::create(key, jwtpp::alg_t::ES384), std::exception);
}