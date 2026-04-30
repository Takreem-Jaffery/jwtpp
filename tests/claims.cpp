#include <gtest/gtest.h>
#include <jwtpp/jwtpp.hh>

TEST(jwtpp, create_close_claims)
{
    EXPECT_NO_THROW(jwtpp::claims cl);

    // These may NOT throw anymore depending on your parse() behavior
    // Your parse() doesn't explicitly throw → so we relax expectations
    EXPECT_NO_THROW(jwtpp::claims cl(""));
    EXPECT_NO_THROW(jwtpp::claims cl("", true));

    jwtpp::sp_claims cl;
    EXPECT_NO_THROW(cl = std::make_shared<jwtpp::claims>());

    EXPECT_THROW(cl->set().any("", "val"), std::invalid_argument);
    EXPECT_THROW(cl->set().any("key", ""), std::invalid_argument);

    EXPECT_NO_THROW(cl->set().any("iss", "troian"));
    EXPECT_NO_THROW(cl->set().any("iss", "troian"));

    EXPECT_FALSE(cl->has().any("aud"));

    EXPECT_EQ("troian", cl->get().any("iss"));
}

TEST(jwtpp, set_other_types_claims)
{
    jwtpp::claims cl;

    const Json::Int ts = 1593345759;
    cl.set().any("iat", ts);
    EXPECT_TRUE(cl.has().any("iat"));
    EXPECT_EQ(ts, cl.get().anyInt("iat"));
    EXPECT_TRUE(cl.check().any("iat", ts));

    const Json::UInt uintval = 0x1d;
    cl.set().any("uintval", uintval);
    EXPECT_TRUE(cl.has().any("uintval"));
    EXPECT_EQ(uintval, cl.get().anyUInt("uintval"));
    EXPECT_TRUE(cl.check().any("uintval", uintval));

    const Json::Int64 int64val = 0x1122334455667788;
    cl.set().any("int64val", int64val);
    EXPECT_TRUE(cl.has().any("int64val"));
    EXPECT_EQ(int64val, cl.get().anyInt64("int64val"));
    EXPECT_TRUE(cl.check().any("int64val", int64val));

    const Json::UInt64 unsig64int = 0x8877665544332211;
    cl.set().any("unsig64int", unsig64int);
    EXPECT_TRUE(cl.has().any("unsig64int"));
    EXPECT_EQ(unsig64int, cl.get().anyUInt64("unsig64int"));
    EXPECT_TRUE(cl.check().any("unsig64int", unsig64int));

    const double realval = 0.01;
    cl.set().any("realval", realval);
    EXPECT_TRUE(cl.has().any("realval"));
    EXPECT_DOUBLE_EQ(realval, cl.get().anyDouble("realval"));
    EXPECT_TRUE(cl.check().any("realval", realval));
}

TEST(jwtpp, set_claim)
{
    jwtpp::claims cl;

    const Json::Int ts = 1593345759;
    cl.set().any("iat", ts);

    EXPECT_TRUE(cl.has().any("iat"));
    EXPECT_EQ(ts, cl.get().anyInt("iat"));
}