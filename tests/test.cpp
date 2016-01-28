#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "crypto.hpp"

TEST_CASE("Encoding") {
    std::string in = "La vita è bella";
    std::string hex, ohex;

    Crypto::Encode<Crypto::HexEncoder>(in, hex);
    Crypto::Decode<Crypto::HexDecoder>(hex, ohex);

    REQUIRE(in == ohex);

    std::string b64, ob64;
    Crypto::Encode<Crypto::B64Encoder>(in, b64);
    Crypto::Decode<Crypto::B64Decoder>(b64, ob64);

    REQUIRE(in == ob64);
}

TEST_CASE("CIPHER") {
    std::string resHash;

    Crypto::Hash<Crypto::SHA256> hash;
    hash.Digest("test", resHash);

    std::stringstream in, out;
    in << "test";
    hash.Digest(&in, &out);

    REQUIRE(resHash == out.str());
}

TEST_CASE("SALSA") {
    std::string resHash;

    Crypto::Hash<Crypto::SHA256> hash;
    hash.Digest("test", resHash);

    Crypto::CryptographicHash<Crypto::HMAC256> shash;
    shash.Key("Pippo");
    shash.Digest("test", resHash);

    std::string ino, inu;
    Crypto::StreamCipher<Crypto::Salsa> salsa(resHash);
    salsa.Encrypt("prova", ino);
    salsa.Decrypt(ino, inu);
}

TEST_CASE("AES_CBC_IV") {
    std::string out3, out4;
    Crypto::BlockCipher<Crypto::AES, Crypto::CBC> aes("pipopipopipopipopipopipopipopipo", "0000000000000000");
    aes.Encrypt("pluto交", out3);
    aes.Decrypt(out3, out4);

    std::stringstream in2, out2, out22;
    in2 << out4;
    aes.Encrypt(in2, out2);
    aes.Decrypt(out2, out22);
    std::string result = out22.str();

    REQUIRE(out4 == result);
    REQUIRE(aes.IV() == std::string("0000000000000000"));
}

TEST_CASE("AES_CBC") {
    std::string out3, out4;
    Crypto::BlockCipher<Crypto::AES, Crypto::CBC> aes("pipopipopipopipopipopipopipopipo");
    aes.Encrypt("pluto交", out3);
    aes.Decrypt(out3, out4);

    std::stringstream in2, out2, out22;
    in2 << out4;
    aes.Encrypt(in2, out2);
    aes.Decrypt(out2, out22);
    std::string result = out22.str();

    REQUIRE(out4 == result);
}

TEST_CASE("AES_CFB_IV") {
    std::string out3, out4;
    Crypto::BlockCipher<Crypto::AES, Crypto::CFB> aes("pipopipopipopipopipopipopipopipo", "0000000000000000");
    aes.Encrypt("pluto交", out3);
    aes.Decrypt(out3, out4);

    std::stringstream in2, out2, out22;
    in2 << out4;
    aes.Encrypt(in2, out2);
    aes.Decrypt(out2, out22);
    std::string result = out22.str();

    REQUIRE(out4 == result);
    REQUIRE(aes.IV() == std::string("0000000000000000"));
}

TEST_CASE("AES_CFB") {
    std::string out3, out4;
    Crypto::BlockCipher<Crypto::AES, Crypto::CFB> aes("pipopipopipopipopipopipopipopipo");
    aes.Encrypt("pluto交", out3);
    aes.Decrypt(out3, out4);

    std::stringstream in2, out2, out22;
    in2 << out4;
    aes.Encrypt(in2, out2);
    aes.Decrypt(out2, out22);
    std::string result = out22.str();

    REQUIRE(out4 == result);
}
