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

namespace jwtpp {

namespace {

//Move Method 
//tokenize() has no dependency on jws state; it is a pure string utility.
//Moving it into an anonymous namespace makes that clear and removes it from the public jws interface.
std::vector<std::string> tokenize(const std::string &text, char sep) {
    std::vector<std::string> tokens;
    std::size_t start = 0;
    std::size_t end   = 0;

    while ((end = text.find(sep, start)) != std::string::npos) {
        tokens.push_back(text.substr(start, end - start));
        start = end + 1;
    }
    tokens.push_back(text.substr(start));
    return tokens;
}

static const std::string BEARER_PREFIX("bearer ");

//Extract Method
//parse() was a 50-line monolith. Each logical phase is now its own named function so the reader can understand the overall flow at a glance and drill into any phase independently.

//Phase 1: strip and validate the "Bearer " prefix
std::string strip_bearer_prefix(const std::string &full_bearer) {
    if (full_bearer.empty() || full_bearer.length() < BEARER_PREFIX.length()) {
        throw std::invalid_argument("Bearer is invalid or empty");
    }
    for (size_t i = 0; i < BEARER_PREFIX.length(); i++) {
        if (BEARER_PREFIX[i] != std::tolower(static_cast<unsigned char>(full_bearer[i]))) {
            throw std::invalid_argument("Bearer header is invalid");
        }
    }
    return full_bearer.substr(BEARER_PREFIX.length());
}

//Phase 2: decode and validate the JWT header segment
alg_t parse_jwt_header(const std::string &encoded_header) {
    Json::Value h = unmarshal_b64(encoded_header);   //propagates on failure

    //Decompose Conditional
    //The original had four sequential if-throw checks interleaved with business logic. Named guard clauses make each invariant readable.
    if (!h.isMember("typ") || !h.isMember("alg")) {
        throw std::runtime_error("Invalid JWT header");
    }
    if (h["typ"].asString() != "JWT") {
        throw std::runtime_error("Is not JWT");
    }

    alg_t a = crypto::str2alg(h["alg"].asString());
    if (a >= alg_t::UNKNOWN) {
        throw std::runtime_error("Invalid alg");
    }
    return a;
}

//Phase 3: decode the claims segment
sp_claims parse_jwt_claims(const std::string &encoded_claims) {
    return std::make_shared<class claims>(encoded_claims, true);
}

} //anonymous namespace


jws::jws(alg_t a, const std::string &data, sp_claims cl, const std::string &sig)
    : _alg(a)
    , _data(data)
    , _claims(cl)
    , _sig(sig)
{}

bool jws::verify(sp_crypto c, verify_cb v) {
    if (!c) {
        throw std::runtime_error("uninitialized crypto");
    }
    if (c->alg() != _alg) {
        throw std::runtime_error("invalid crypto alg");
    }
    if (!c->verify(_data, _sig)) {
        return false;
    }
    //Decompose Conditional
    //The optional callback invocation is now a clear early-return guard.
    return v ? v(_claims) : true;
}

sp_jws jws::parse(const std::string &full_bearer) {
    //Extract Method
    //The original 50-line body is now a readable 5-step pipeline.
    const std::string bearer = strip_bearer_prefix(full_bearer);

    const auto tokens = tokenize(bearer, '.');
    if (tokens.size() != 3) {
        throw std::runtime_error("Bearer is invalid");
    }

    const alg_t    a  = parse_jwt_header(tokens[0]);
    const sp_claims cl = parse_jwt_claims(tokens[1]);

    //Replace Temp with Query
    //The original built `d` across three separate string-concat statements.
    //Expressed as a single initialiser the intent is immediately clear.
    const std::string signed_data = tokens[0] + "." + tokens[1];

    //Replace Constructor with Factory Method
    //Raw `new jws(...)` wrapped in a bare try/catch that only rethrew was noise. make_shared expresses ownership intent and the redundant try/catch is removed (Replace Error Code with Exception principle: don't catch what you cannot handle).
    return std::make_shared<jws>(a, signed_data, cl, tokens[2]);
}

//Inline Method
//jws::sign() was a single-line wrapper around c->sign(data) with no added value.  All three former callers now invoke the crypto object directly.
//The static helper is removed from the public interface.

std::string jws::sign_claims(class claims &cl, sp_crypto c) {
    //Form Template Method
    //sign_claims and sign_bearer both produce a dot-separated JWT string;
    //sign_bearer just prepends "Bearer ".The shared structure is made visible by having sign_bearer delegate entirely to sign_claims.
    hdr h(c->alg());
    const std::string payload = h.b64() + "." + cl.b64();

    //Replace Temp with Query
    //`sig` was a named temp used exactly once immediately after assignment.
    return payload + "." + c->sign(payload);   //sign() inlined here
}

std::string jws::sign_bearer(class claims &cl, sp_crypto c) {
    return "Bearer " + jws::sign_claims(cl, c);
}

} //namespace jwtpp