#ifndef CRYPTO_H
#define CRYPTO_H

#include <memory>
#include <array>

#include <Cryptopp/seckey.h>
#include <Cryptopp/modes.h>
#include <Cryptopp/rsa.h>
#include <Cryptopp/hmac.h> 
#include <Cryptopp/sha.h>
#include <Cryptopp/aes.h>
#include <Cryptopp/salsa.h>
#include <Cryptopp/hex.h>
#include <Cryptopp/base64.h>
#include <Cryptopp/osrng.h>
#include <Cryptopp/files.h>

//TODO: use arraysink, remove strings
namespace Crypto {

typedef CryptoPP::HexEncoder HexEncoder;
typedef CryptoPP::HexDecoder HexDecoder;

typedef CryptoPP::Base64Encoder B64Encoder;
typedef CryptoPP::Base64Decoder B64Decoder;

template <typename S>
void Encode(const std::string& in, std::string& out) {
    S encoder;
    encoder.Attach(new CryptoPP::StringSink(out));
    encoder.Put(reinterpret_cast<const byte*>(in.c_str()), in.size());
    encoder.MessageEnd();
}

template <typename S> 
void Decode(const std::string& in, std::string& out) {
    S decoder;
    decoder.Attach(new CryptoPP::StringSink(out));
    decoder.Put(reinterpret_cast<const byte*>(in.c_str()), in.size());
    decoder.MessageEnd();
}

void RandomIV(byte* iv, const int size) {
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock(iv, size);
}

class RSA {
public:
    RSA() {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 3072);

        privateKey = CryptoPP::RSA::PrivateKey(params);
        publicKey = CryptoPP::RSA::PublicKey(params);
    }

    RSA(CryptoPP::RSA::PublicKey& pub, CryptoPP::RSA::PrivateKey& priv)
        : publicKey(pub), privateKey(priv)
    {}

    void Encrypt(const std::string& in, std::string& out) {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA>>::Encryptor enc(publicKey);

        CryptoPP::StringSource ss1(in, true,
            new CryptoPP::PK_EncryptorFilter(rng, enc,
                new CryptoPP::StringSink(out)
            )
        );
    }

    void Decrypt(const std::string& in, std::string& out) {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA>>::Decryptor dec(privateKey);

        CryptoPP::StringSource ss2(in, true,
            new CryptoPP::PK_DecryptorFilter(rng, dec,
                new CryptoPP::StringSink(out)
            )
        );
    }

private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
};

typedef CryptoPP::Salsa20 Salsa;
typedef CryptoPP::SHA256 Sha256;
typedef CryptoPP::HMAC<Sha256> HMacSha256;
typedef CryptoPP::AES AES;
typedef CryptoPP::CBC_Mode_ExternalCipher CBC;
typedef CryptoPP::CFB_Mode_ExternalCipher CFB;

template <typename T>
class StreamCipher {
public:
    StreamCipher(const std::string& key, size_t s = T::DEFAULT_KEYLENGTH) : _keyLength(s) {
        assert(key.size() == _keyLength);
        _key.Assign(reinterpret_cast<const byte*>(key.c_str()), _keyLength);
        RandomIV(_iv.data(), T::IV_LENGTH);
    }

    StreamCipher(const std::string& key, const std::string& iv, size_t s = T::DEFAULT_KEYLENGTH) : _keyLength(s) {
        assert(key.size() == _keyLength);
        _key.Assign(key.c_str(), _keyLength);
        memcpy(_iv.data(), iv.c_str(), T::IV_LENGTH);
    }

    void Encrypt(const std::string& plain, std::string& cipher) {
        typename T::Encryption enc(_key.data(), _keyLength, _iv.data());
        size_t size = plain.size();
        std::unique_ptr<char> cPtr(new char[size]);
        enc.ProcessData(
            reinterpret_cast<byte*>(cPtr.get()),
            reinterpret_cast<const byte*>(plain.c_str()),
            size
        );
        cipher = std::move(std::string(cPtr.get(), size));
    }

    void Decript(const std::string& cipher, std::string& plain) {
        typename T::Decryption dec(_key.data(), _keyLength, _iv.data());
        size_t size = cipher.size();
        std::unique_ptr<char> cPtr(new char[size]);
        dec.ProcessData(
            reinterpret_cast<byte*>(cPtr.get()),
            reinterpret_cast<const byte*>(cipher.c_str()),
            cipher.size()
        );
        plain = std::move(std::string(cPtr.get(), size));
    }

private:
    std::array<byte, T::IV_LENGTH> _iv;
    CryptoPP::SecByteBlock _key;

    const size_t _keyLength;
};

template <typename T, typename V>
struct decryption_traits {};

template <>
struct decryption_traits<AES, CFB> {
    typedef AES::Encryption CipherDecriptor;
    typedef CFB::Encryption ModDecriptor;
};

template <>
struct decryption_traits<AES, CBC> {
    typedef AES::Decryption CipherDecriptor;
    typedef CBC::Decryption ModDecriptor;
};


template <typename T, typename V>
class BlockCipher {
public:
    BlockCipher(const std::string& key, size_t s = T::MAX_KEYLENGTH) : _keyLength(s) {
        assert(key.size() == _keyLength);
        _key.Assign(reinterpret_cast<const byte*>(key.c_str()), _keyLength);
        RandomIV(_iv.data(), T::BLOCKSIZE);
    }

    BlockCipher(const std::string& key, const std::string& iv, size_t s = T::MAX_KEYLENGTH) : _keyLength(s)  {
        assert(key.size() == _keyLength);
        _key.Assign(reinterpret_cast<const byte*>(key.c_str()), _keyLength);
        memcpy(_iv.data(), iv.c_str(), T::BLOCKSIZE);
    }

    void Encrypt(std::istream& i, std::ostream& o) {
        typename T::Encryption enc(_key.data(), _keyLength);
        typename V::Encryption mod(enc, _iv.data());

        CryptoPP::FileSource(i, true,
            new CryptoPP::StreamTransformationFilter(mod,
                new CryptoPP::FileSink(o)
            )
         );
    }

    void Encrypt(const std::string& plain, std::string& cipher) {
        typename T::Encryption enc(_key.data(), _keyLength);
        typename V::Encryption mod(enc, _iv.data());

        CryptoPP::StreamTransformationFilter str(mod, new CryptoPP::StringSink(cipher));
        str.Put(reinterpret_cast<const byte*>(plain.c_str()), plain.length());
        str.MessageEnd();
    }

    void Decrypt(std::istream& i, std::ostream& o) {
        decryption_traits<T, V>::CipherDecriptor dec(_key.data(), _keyLength);
        decryption_traits<T, V>::ModDecriptor mod(dec, _iv.data());

        CryptoPP::FileSource(i, true,
            new CryptoPP::StreamTransformationFilter(mod,
                new CryptoPP::FileSink(o)
            )
        );
    }

    void Decrypt(const std::string& cipher, std::string& plain) {
        decryption_traits<T, V>::CipherDecriptor dec(_key.data(), _keyLength);
        decryption_traits<T, V>::ModDecriptor mod(dec, _iv.data());

        CryptoPP::StreamTransformationFilter str(mod, new CryptoPP::StringSink(plain));
        str.Put(reinterpret_cast<const byte*>(cipher.c_str()), cipher.size());
        str.MessageEnd();
    }

private:
    std::array<byte, T::BLOCKSIZE> _iv;
    CryptoPP::SecByteBlock _key;

    const size_t _keyLength;
};

template <typename T>
class Hash {
public:
    void Digest(const std::string& msg, std::string& out) {
        engine.CalculateDigest(
            _hash.data(),
            reinterpret_cast<const byte*>(msg.c_str()),
            msg.length()
        );
        out = std::move(std::string(reinterpret_cast<char*>(_hash.data()), T::DIGESTSIZE));
    }

    void Digest(std::istream* const i, std::ostream* const o) {
        CryptoPP::FileSource(*i, true,
            new CryptoPP::HashFilter(engine,
                new CryptoPP::FileSink(*o)
            )
         );
    }

protected:
    T engine;

private:
    std::array<byte, T::DIGESTSIZE> _hash;
};

template <typename T>
class CryptographicHash : public Hash<T> {
public:
    void Key(const std::string& key) {
        this->engine.SetKey(
            reinterpret_cast<const byte*>(key.c_str()),
            key.length()
        );
    }

};

}

#endif
