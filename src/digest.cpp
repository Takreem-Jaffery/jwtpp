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

#include <sstream>
#include <iomanip>
#include <cstring>

#include <jwtpp/jwtpp.hh>

#include <openssl/sha.h>

namespace jwtpp {

// -----------------------------------------------------------------------
// REFACTORING: Extract Method
//
// The original constructor had three near-identical blocks for SHA256,
// SHA384, and SHA512 — each performing: set _size, declare ctx, Init,
// Update, Final, throw on failure. That repeated structure is extracted
// into compute_sha256/384/512 helpers so each case in the switch is a
// single, readable call.
//
// REFACTORING: Decompose Conditional
//
// The large switch in the constructor mixed the decision of *which*
// algorithm to use with the mechanics of *how* to compute it. After
// extracting the helpers, the switch becomes a clean dispatcher that
// separates intent (which hash) from implementation (how to hash).
// -----------------------------------------------------------------------
 
static void compute_sha256(const uint8_t *in_data, size_t in_size,
                            uint8_t *out, size_t &out_size)
{
    out_size = SHA256_DIGEST_LENGTH;
    SHA256_CTX sha_ctx;
 
    if (SHA256_Init(&sha_ctx) != 1) {
        throw std::runtime_error("Couldn't init SHA256");
    }
    if (SHA256_Update(&sha_ctx, in_data, in_size) != 1) {
        throw std::runtime_error("Couldn't calculate hash");
    }
    if (SHA256_Final(out, &sha_ctx) != 1) {
        throw std::runtime_error("Couldn't finalize SHA");
    }
}
 
static void compute_sha384(const uint8_t *in_data, size_t in_size,
                            uint8_t *out, size_t &out_size)
{
    out_size = SHA384_DIGEST_LENGTH;
    SHA512_CTX sha_ctx;
 
    if (SHA384_Init(&sha_ctx) != 1) {
        throw std::runtime_error("Couldn't init SHA384");
    }
    if (SHA384_Update(&sha_ctx, in_data, in_size) != 1) {
        throw std::runtime_error("Couldn't calculate hash");
    }
    if (SHA384_Final(out, &sha_ctx) != 1) {
        throw std::runtime_error("Couldn't finalize SHA");
    }
}
 
static void compute_sha512(const uint8_t *in_data, size_t in_size,
                            uint8_t *out, size_t &out_size)
{
    out_size = SHA512_DIGEST_LENGTH;
    SHA512_CTX sha_ctx;
 
    if (SHA512_Init(&sha_ctx) != 1) {
        throw std::runtime_error("Couldn't init SHA512");
    }
    if (SHA512_Update(&sha_ctx, in_data, in_size) != 1) {
        throw std::runtime_error("Couldn't calculate hash");
    }
    if (SHA512_Final(out, &sha_ctx) != 1) {
        throw std::runtime_error("Couldn't finalize SHA");
    }
}
 
// -----------------------------------------------------------------------
// Constructor: now a clean dispatcher — intent (which hash) is separated
// from implementation (how to hash) via the extracted helpers above.
// -----------------------------------------------------------------------
digest::digest(digest::type type, const uint8_t *in_data, size_t in_size)
    : _size(SHA256_DIGEST_LENGTH)
    , _data(new uint8_t[SHA512_DIGEST_LENGTH], std::default_delete<uint8_t[]>())
{
    // When in_data is nullptr the call comes from a subclass constructor
    // which will populate _size, _data, and compute the hash itself.
    if (in_data == nullptr) {
        return;
    }

    switch (type) {
    case digest::type::SHA256:
        compute_sha256(in_data, in_size, _data.get(), _size);
        break;
    case digest::type::SHA384:
        compute_sha384(in_data, in_size, _data.get(), _size);
        break;
    case digest::type::SHA512:
        compute_sha512(in_data, in_size, _data.get(), _size);
        break;
    }
}
 
digest::~digest() {
    std::memset(_data.get(), 0, _size);
}
 
size_t digest::size() const {
    return _size;
}
 
uint8_t *digest::data() {
    return _data.get();
}
 
std::string digest::to_string() const {
    std::stringstream s;
    for (size_t i = 0; i < size() / 2; ++i) {
        s << std::hex << std::setfill('0') << std::setw(2)
          << (_data.get()[i * 2] << 8 | _data.get()[(i * 2) + 1]);
    }
    return s.str();
}

// ---------------------------------------------------------------------------
// Subclass implementations — Replace Type Code with Subclass
//
// Each subclass constructor handles exactly one SHA algorithm.
// There is no switch and no type code — the algorithm is encoded in the
// type name itself. The base class size(), data(), and to_string() are
// inherited, so only the constructor is needed per subclass.
//
// The base class constructor and its switch are preserved so that all
// existing callers (rsa.cpp, pss.cpp, ecdsa.cpp etc.) using the form:
//     digest d(_hash_type, data, len);
// continue to compile and run without any modification.
// ---------------------------------------------------------------------------

// --- Sha256Digest -----------------------------------------------------------

Sha256Digest::Sha256Digest(const uint8_t *in_data, size_t in_size)
    : digest(digest::type::SHA256, nullptr, 0)
{
    _size = SHA256_DIGEST_LENGTH;
    _data = std::shared_ptr<uint8_t>(
        new uint8_t[SHA512_DIGEST_LENGTH],
        std::default_delete<uint8_t[]>());

    compute_sha256(in_data, in_size, _data.get(), _size);
}

size_t   Sha256Digest::size() const { return _size;       }
uint8_t *Sha256Digest::data()       { return _data.get(); }
std::string Sha256Digest::to_string() const {
    std::stringstream s;
    for (size_t i = 0; i < _size / 2; ++i) {
        s << std::hex << std::setfill('0') << std::setw(2)
          << (_data.get()[i * 2] << 8 | _data.get()[(i * 2) + 1]);
    }
    return s.str();
}

// --- Sha384Digest -----------------------------------------------------------

Sha384Digest::Sha384Digest(const uint8_t *in_data, size_t in_size)
    : digest(digest::type::SHA384, nullptr, 0)
{
    _size = SHA384_DIGEST_LENGTH;
    _data = std::shared_ptr<uint8_t>(
        new uint8_t[SHA512_DIGEST_LENGTH],
        std::default_delete<uint8_t[]>());

    compute_sha384(in_data, in_size, _data.get(), _size);
}

size_t   Sha384Digest::size() const { return _size;       }
uint8_t *Sha384Digest::data()       { return _data.get(); }
std::string Sha384Digest::to_string() const {
    std::stringstream s;
    for (size_t i = 0; i < _size / 2; ++i) {
        s << std::hex << std::setfill('0') << std::setw(2)
          << (_data.get()[i * 2] << 8 | _data.get()[(i * 2) + 1]);
    }
    return s.str();
}

// --- Sha512Digest -----------------------------------------------------------

Sha512Digest::Sha512Digest(const uint8_t *in_data, size_t in_size)
    : digest(digest::type::SHA512, nullptr, 0)
{
    _size = SHA512_DIGEST_LENGTH;
    _data = std::shared_ptr<uint8_t>(
        new uint8_t[SHA512_DIGEST_LENGTH],
        std::default_delete<uint8_t[]>());

    compute_sha512(in_data, in_size, _data.get(), _size);
}

size_t   Sha512Digest::size() const { return _size;       }
uint8_t *Sha512Digest::data()       { return _data.get(); }
std::string Sha512Digest::to_string() const {
    std::stringstream s;
    for (size_t i = 0; i < _size / 2; ++i) {
        s << std::hex << std::setfill('0') << std::setw(2)
          << (_data.get()[i * 2] << 8 | _data.get()[(i * 2) + 1]);
    }
    return s.str();
}

} // namespace jwtpp





















































