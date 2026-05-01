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

// REFACTORING: Removed unused #include <iostream>

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

// REFACTORING: Replace temporary variable with query
// The local variable 'out' was inlined directly into the return statement,
// eliminating unnecessary temporary storage.
std::string marshal(const Json::Value &json) {
	Json::StreamWriterBuilder builder;
	builder["commentStyle"] = "None";
	builder["indentation"] = ""; // Write in one line
	return Json::writeString(builder, json);
}

// REFACTORING: Replace temporary variable with query
// The local variable 's' was inlined directly into the b64::encode_uri() call,
// eliminating intermediate storage and making the data flow clearer.
std::string marshal_b64(const Json::Value &json) {
	return b64::encode_uri(marshal(json));
}

Json::Value unmarshal(const std::string &in) {
	Json::Value j;
	std::stringstream(in) >> j;

	return j;
}

// REFACTORING: Replace temporary variable with query
// The local variable 'decoded' was inlined directly into the unmarshal() call,
// eliminating unnecessary temporary storage and making intent clearer.
// Also renamed parameter from 'b64' to 'encoded' to avoid shadowing the b64 class name.
Json::Value unmarshal_b64(const std::string &encoded) {
	return unmarshal(b64::decode(encoded));
}

} // namespace jwtpp
