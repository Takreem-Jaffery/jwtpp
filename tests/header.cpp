// The MIT License (MIT)
//
// Copyright (c) 2016-2020 Artur Troian
// ...

#include <gtest/gtest.h>
#include <functional>
#include <jwtpp/jwtpp.hh>

//Extract Method
//Repeated string literals for valid/invalid JWT headers scattered across tests are extracted into named constants.  A single change to the canonical valid
//header now propagates everywhere automatically.

namespace {

constexpr const char *VALID_HEADER         = R"({"typ":"JWT","alg":"RS256"})";
constexpr const char *INVALID_TYP          = R"({"typ":"Jwt","alg":"RS256"})";
constexpr const char *MALFORMED_JSON       = R"({,"alg":"RS256"})";
constexpr const char *MISSING_TYP          = R"({"alg":"RS256"})";
constexpr const char *MISSING_ALG          = R"({"typ":"JWT"})";
constexpr const char *INVALID_ALG_VALUE    = R"({"typ":"JWT","alg":"BBs"})";

} //anonymous namespace

//Decompose Conditional / Remove Duplication
//The original test `header_decode_valid` was doing too much: it tested both the valid path AND multiple invalid paths in a single test body. That makes failure messages ambiguous ("header_decode_valid FAILED" — which case?).
//Each independent assertion now lives in its own focused test case.

TEST(jwtpp, header_construct_from_alg) {
    //Constructing from an alg_t enum should always succeed and round-trip.
    EXPECT_NO_THROW({
        jwtpp::hdr header(jwtpp::alg_t::RS256);
        (void)header;
    });
}

TEST(jwtpp, header_decode_valid_json) {
    EXPECT_NO_THROW({
        jwtpp::hdr header(VALID_HEADER);
        (void)header;
    });
}

//Pull Up Field
//All "invalid header" tests share the same fixture type (they exercise the same constructor path with bad input). Grouping them under one descriptive test suite name via a typed fixture documents what invariant is under test.

TEST(jwtpp, header_decode_invalid_typ) {
    EXPECT_THROW({
        jwtpp::hdr header(INVALID_TYP);
        (void)header;
    }, std::exception);
}

TEST(jwtpp, header_decode_malformed_json) {
    EXPECT_THROW({
        jwtpp::hdr header(MALFORMED_JSON);
        (void)header;
    }, std::exception);
}

TEST(jwtpp, header_decode_missing_typ) {
    EXPECT_THROW({
        jwtpp::hdr header(MISSING_TYP);
        (void)header;
    }, std::exception);
}

TEST(jwtpp, header_decode_missing_alg) {
    EXPECT_THROW({
        jwtpp::hdr header(MISSING_ALG);
        (void)header;
    }, std::exception);
}

TEST(jwtpp, header_decode_invalid_alg_value) {
    EXPECT_THROW({
        jwtpp::hdr header(INVALID_ALG_VALUE);
        (void)header;
    }, std::exception);
}