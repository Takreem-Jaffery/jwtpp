#include <gtest/gtest.h>
#include <jwtpp/jwtpp.hh>

TEST(jwtpp, create_close_claims)
{
    EXPECT_NO_THROW(jwtpp::claims cl);

    // The constructor parses immediately, so empty and malformed input
    // must still be treated as errors instead of being silently accepted.
    EXPECT_THROW(jwtpp::claims cl(""), std::exception);
    EXPECT_THROW(jwtpp::claims cl("", true), std::exception);
    EXPECT_THROW(jwtpp::claims cl("jkhfkjsgdfg"), std::exception);

    jwtpp::sp_claims cl;

    EXPECT_NO_THROW(cl = std::make_shared<jwtpp::claims>());

    // Empty keys and values are rejected by the string setter.
    EXPECT_THROW(cl->set("", "val"), std::invalid_argument);
    EXPECT_THROW(cl->set("key", ""), std::invalid_argument);

    EXPECT_NO_THROW(cl->set("iss", "troian"));
    EXPECT_NO_THROW(cl->set("iss", "troian"));

    EXPECT_FALSE(cl->has("aud"));

    EXPECT_EQ("troian", cl->get("iss"));
}

TEST(jwtpp, set_other_types_claims)
{
    jwtpp::claims cl;

    const Json::Int ts = 1593345759;

    cl.set("iat", ts);

    EXPECT_TRUE(cl.has("iat"));
    EXPECT_EQ(ts, cl.getInt("iat"));
    EXPECT_TRUE(cl.check("iat", ts));

    const Json::UInt uintval = 0x1d;

    cl.set("uintval", uintval);

    EXPECT_TRUE(cl.has("uintval"));
    EXPECT_EQ(uintval, cl.getUInt("uintval"));
    EXPECT_TRUE(cl.check("uintval", uintval));

    const Json::Int64 int64val = 0x1122334455667788;

    cl.set("int64val", int64val);

    EXPECT_TRUE(cl.has("int64val"));
    EXPECT_EQ(int64val, cl.getInt64("int64val"));
    EXPECT_TRUE(cl.check("int64val", int64val));

    const Json::UInt64 unsig64int = 0x8877665544332211;

    cl.set("unsig64int", unsig64int);

    EXPECT_TRUE(cl.has("unsig64int"));
    EXPECT_EQ(unsig64int, cl.getUInt64("unsig64int"));
    EXPECT_TRUE(cl.check("unsig64int", unsig64int));

    const double realval = 0.01;

    cl.set("realval", realval);

    EXPECT_TRUE(cl.has("realval"));
    EXPECT_DOUBLE_EQ(realval, cl.getDouble("realval"));
    EXPECT_TRUE(cl.check("realval", realval));
}

TEST(jwtpp, set_claim)
{
    jwtpp::claims cl;

    const Json::Int ts = 1593345759;

    cl.set("iat", ts);

    EXPECT_TRUE(cl.has("iat"));
    EXPECT_EQ(ts, cl.getInt("iat"));
}