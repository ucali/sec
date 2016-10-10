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

    std::string oo;
    hash.Digest(in, oo);

    REQUIRE(resHash == oo);
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
    aes.Encrypt("pluto", out3);
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
    aes.Encrypt("pluto", out3);
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
    aes.Encrypt("pluto", out3);
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
    aes.Encrypt("pluto", out3);
    aes.Decrypt(out3, out4);

    std::stringstream in2, out2, out22;
    in2 << out4;
    aes.Encrypt(in2, out2);
    aes.Decrypt(out2, out22);
    std::string result = out22.str();

    REQUIRE(out4 == result);
}


TEST_CASE("AES_CFB_FILE") {
    Crypto::BlockCipher<Crypto::AES, Crypto::CFB> aes("pipopipopipopipopipopipopipopipo");

    std::fstream temp;
    temp.open("test.bin", std::ios::out | std::ios::binary);
    REQUIRE(temp.is_open());

    std::stringstream in, out;
    in << "sample string 1" << std::endl;
    in << "sample string 2" << std::endl;
    in << "sample string 3" << std::endl;
    in << "sample string 4" << std::endl;
    aes.Encrypt(in, temp);
    temp.close();

    temp.open("test.bin", std::ios::in | std::ios::binary);
    aes.Decrypt(temp, out);

    std::string result = out.str();

    REQUIRE(result != "");
}

TEST_CASE("AES_GCM") {
    Crypto::AuthBlockCipher<Crypto::AES, Crypto::GCM<Crypto::AES>> aes("pipopipopipopipopipopipopipopipo");

    std::string ch, plain;
    aes.Encrypt("test", ch);
    aes.Decrypt(ch, plain);

    REQUIRE(plain == "test");
}

TEST_CASE("RSA") {
    Crypto::RSA rsa;

    std::string ch, plain;
    rsa.Encrypt("test", ch);
    rsa.Decrypt(ch, plain);

    REQUIRE(plain == "test");
}

bool LoadKey(CryptoPP::RandomNumberGenerator& rng, const std::string& file, CryptoPP::RSA::PrivateKey& key) {
    CryptoPP::ByteQueue q;
    CryptoPP::FileSource KeyFile(file.c_str(), true, new CryptoPP::Base64Decoder);
    KeyFile.TransferTo(q);
    key.BERDecodePrivateKey(q,false,0); // last 2 params unused
    return key.Validate(rng, 2);
}



TEST_CASE("RSA_GO") {
    std::string key =
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAI634OdGUv7lW88/\n"
            "yJTmrlBAmn/Muif7Mpr+62zLlww7wk9tWhDiZtbdxNQxL+Zw5qMLfc5t43rwYa0H\n"
            "CKoEIM5F6eRM/gLCsZVV7Fcw8VcLbyDPT9IHJkaM6msXOXm907dhBVqgiTzdEVql\n"
            "FrkFuyRNDDsCEUP2/Rfquuw1hGqxAgMBAAECgYBVO/QRq6o9mPUv3UQJyYspWqvq\n"
            "z3YOErOyZbRskVpwb/AoR4KWut/4SxIWOBoHYj4b+ez0sCQ/c/ihwaWnBDgilEov\n"
            "DRavE79/XUxnV2U92w/V+oyvoqYcD7n5TL+XlTyDBeDTnVUgkTopWUWv/p3t6mt3\n"
            "dc0N7aYmQtyBd4QlUQJBAMwFEFGBXYf1DFm+LN5002tPo1HDN+LdfBxAOMpOxCOO\n"
            "IocQWhdpgotLKjTgQr3aKqzk8uJj1bwIm6/4JvrKnpMCQQCzFIAcNG+Ulnl3K/an\n"
            "EN+cXua5/ko+7rjEtiwVByVWU8KD9j+FU1V//EbCNllehd+yP7SIZw4k2OJp4zWz\n"
            "qhgrAkB8hAKnm+q3lYlKJFVCF88IyXwF5L1xCng6zb9bSaNPh+nuwL4bV9vCo8dI\n"
            "qi5RrJsrFjhej0vdDOvoA+3WVl9dAkAOkz6SDRp/x3d/YY6jrlXkzjyNKss0MA3N\n"
            "xN31oC1Dx3FveB1XZp7w2cGQkQfZD6BTS6gP6gNWsGhNIfb+9nsdAkEAgeCoU4qs\n"
            "FMtfiOJHkEaunoHtiuVZfUyam1Zb1ZOYcsF+RrTKQ65o3eojMZzsGgDrWdw6kvXM\n"
            "ycvsWE0b3PEErQ==\n";

    std::string b;

    Crypto::Decode<Crypto::B64Decoder>(key, b);

    CryptoPP::RSA::PublicKey pub;
    CryptoPP::RSA::PrivateKey k;
    CryptoPP::ByteQueue q;
    q.Put((byte*)b.c_str(), b.size());
    k.BERDecodePrivateKey(q,false,0); // last 2 params unused

    Crypto::RSA rsa(pub, k);

    std::string hex = "554facc2f42bc2f8ee438824b833c7ea77fdaccc752ddab06872b0d73e5dda797beac79d75f0f4294beed04adee46a149f803d3ed1344f93cabe41a629a5b8da9adb39ead14495814b5498458cf7dbee75fa62f185d812db59a2f4e5b5a1551ac3e6f246e6e7e4c55a157f952a791171cb98fb64050645f510e1d13395ac07e5";

    std::string ch, plain;
    Crypto::Decode<Crypto::HexDecoder>(hex, ch);

    std::cout << ch << std::endl;
    rsa.Decrypt(ch, plain);

    std::cout << plain << std::endl;
}


