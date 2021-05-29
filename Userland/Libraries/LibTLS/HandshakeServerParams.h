/*
 * Copyright (c) 2021, Dex♪ <dexes.ttp@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Variant.h>

namespace TLS {

// Defined in RFC 5246 section 7.4.3
struct ServerDHEParams {
    ByteBuffer client_random {};
    ByteBuffer server_random {};
    ByteBuffer dh_p {};
    ByteBuffer dh_g {};
    ByteBuffer dh_Ys {};
};

// Defined in RFC 5246 section 7.4.3
struct ServerDHAnonParams {
    ByteBuffer dh_p {};
    ByteBuffer dh_g {};
    ByteBuffer dh_Ys {};
};

enum class NamedCurve: u16 {
    // Defined in RFC 4492 section 5.1.1
    sect163k1 = 1,
    sect163r1 = 2,
    sect163r2 = 3,
    sect193r1 = 4,
    sect193r2 = 5,
    sect233k1 = 6,
    sect233r1 = 7,
    sect239k1 = 8,
    sect283k1 = 9,
    sect283r1 = 10,
    sect409k1 = 11,
    sect409r1 = 12,
    sect571k1 = 13,
    sect571r1 = 14,
    secp160k1 = 15,
    secp160r1 = 16,
    secp160r2 = 17,
    secp192k1 = 18,
    secp192r1 = 19,
    secp224k1 = 20,
    secp224r1 = 21,
    secp256k1 = 22,
    secp256r1 = 23,
    secp384r1 = 24,
    secp521r1 = 25,

    // Defined in RFC 4492 section 5.1.1
    arbitrary_explicit_prime_curves = 0xFF01,
    arbitrary_explicit_char2_curves = 0xFF02,
};

// Defined in RFC 4492 section 5.4
enum class ECCurveType: u8 {
    ExplicitPrime = 1,
    ExplicitChar2 = 2,
    NamedCurve = 3,
};

enum class ECBasisType: u8 {
    Trinomial = 0,
    Pentanomial = 1,
};

struct ECCurve {
    // 8-bit size
    ByteBuffer a {};
    // 8-bit size
    ByteBuffer b {};
};
struct ECPoint {
    // 8-bit size
    ByteBuffer p {};
};


struct ECExplicitPrime {
    ByteBuffer prime_p {}; // 8-bit size prefix
    ECCurve curve;
    ECPoint base;
    ByteBuffer order {}; // 8-bit size prefix
    ByteBuffer cofactor {}; // 8-bit size prefix
};

struct EcExpliciChar2Trinomial {
    ByteBuffer k {}; // 8-bit size prefix
};

struct EcExpliciChar2Pentanomial {
    ByteBuffer k1 {}; // 8-bit size prefix
    ByteBuffer k2 {}; // 8-bit size prefix
    ByteBuffer k3 {}; // 8-bit size prefix
};

struct ECExplicitChar2 {
    u16 m;
    ECBasisType basis;
    Variant<EcExpliciChar2Trinomial, EcExpliciChar2Pentanomial> curve_data;
    ECCurve curve;
    ECPoint base;
    ByteBuffer order {}; // 8-bit size prefix
    ByteBuffer cofactor {}; // 8-bit size prefix
};

struct ECParameters {
    ECCurveType curve_type;
    Variant<ECExplicitPrime, ECExplicitChar2, NamedCurve> curve_data;
};

struct ServerECDHParams {
    ECParameters curve_params;
    ECPoint public;
    // Size: sha_size
    // Should be SHA(ClientHello.random + ServerHello.random + ServerKeyExchange.params)
    ByteBuffer signed_params;
};

}
