#ifndef CRYPTO_H
#define CRYPTO_H

#include <memory>
#include <array>
#include <type_traits>

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

namespace Crypto {

typedef CryptoPP::HexEncoder HexEncoder;
typedef CryptoPP::HexDecoder HexDecoder;

typedef CryptoPP::Base64Encoder B64Encoder;
typedef CryptoPP::Base64Decoder B64Decoder;

template <typename S>
inline void Encode(const std::string& in, std::string& out) {
    S encoder;
    encoder.Attach(new CryptoPP::StringSink(out));
    encoder.Put(reinterpret_cast<const byte*>(in.c_str()), in.size());
    encoder.MessageEnd();
}

template <typename S> 
inline void Decode(const std::string& in, std::string& out) {
    S decoder;
    decoder.Attach(new CryptoPP::StringSink(out));
    decoder.Put(reinterpret_cast<const byte*>(in.c_str()), in.size());
    decoder.MessageEnd();
}

template <typename T, size_t s>
inline std::array<byte, s> RandomIV() {
    std::array<byte, s> iv;
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock(iv.data(), s);
    return std::move(iv);
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

typedef CryptoPP::SHA1 SHA1;
typedef CryptoPP::SHA256 SHA256;
typedef CryptoPP::SHA512 SHA512;
typedef CryptoPP::HMAC<SHA1> HMAC1;
typedef CryptoPP::HMAC<SHA256> HMAC256;
typedef CryptoPP::HMAC<SHA512> HMAC512;

typedef CryptoPP::AES AES;
typedef CryptoPP::CBC_Mode_ExternalCipher CBC;
typedef CryptoPP::CFB_Mode_ExternalCipher CFB;
typedef CryptoPP::Salsa20 Salsa;

template <typename T>
struct key_traits {
    enum Len {
        DEFAULT = T::DEFAULT_KEYLENGTH,
        MAX = T::MAX_KEYLENGTH,
        MIN = T::MIN_KEYLENGTH
    };
};

template <typename T, size_t L>
class Cipher {
public:
    Cipher(const std::string& key) : _iv(RandomIV<T, L>()) {
        _key.Assign(reinterpret_cast<const byte*>(key.c_str()), key.size());
    }
    Cipher(const std::string& key, const std::string& iv) {
        _key.Assign(reinterpret_cast<const byte*>(key.c_str()), key.size());
        memcpy(_iv.data(), iv.c_str(), L);
    }

    std::string IV() const { return std::move(std::string(reinterpret_cast<const char*>(_iv.data()), _iv.size())); }

protected:
    const byte* iv() const { return _iv.data(); }
    const byte* key() const { return _key.data(); }
    const size_t keySize() const { return _key.size(); }

private:
    std::array<byte, L> _iv;
    CryptoPP::SecByteBlock _key;
};

template <typename K>
struct Message {
    K Data;
    std::string IV;
};

template <typename T>
class StreamCipher : public Cipher<T, T::IV_LENGTH> {
public:
    StreamCipher(const std::string& key) : Cipher<T, T::IV_LENGTH>(key) {}

    StreamCipher(const std::string& key, const std::string& iv) : Cipher<T, T::IV_LENGTH>(key, iv) {}

    void Encrypt(const std::string& plain, std::string& cipher) {
        size_t size = plain.size();
        std::unique_ptr<char> cPtr(new char[size]);

        typename T::Encryption enc(key(), keySize(), iv());
        enc.ProcessData(
            reinterpret_cast<byte*>(cPtr.get()),
            reinterpret_cast<const byte*>(plain.c_str()),
            size
        );
        cipher = std::move(std::string(cPtr.get(), size));
    }

    void Decrypt(const std::string& cipher, std::string& plain) {
        typename T::Decryption dec(key(), keySize(), iv());
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
    CryptoPP::SecByteBlock _key;
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
class BlockCipher : public Cipher<T, T::BLOCKSIZE> {
public:
    BlockCipher(const std::string& key) : Cipher<T, T::BLOCKSIZE>(key) {}
    BlockCipher(const std::string& key, const std::string& iv) : Cipher<T, T::BLOCKSIZE>(key, iv) {}

    void Encrypt(std::istream& i, std::ostream& o) {
        typename T::Encryption enc(key(), keySize());
        typename V::Encryption mod(enc, iv());

        CryptoPP::FileSource(i, true,
            new CryptoPP::StreamTransformationFilter(mod,
                new CryptoPP::FileSink(o)
            )
         );
    }

    void Encrypt(const std::string& plain, std::string& cipher) {
        typename T::Encryption enc(key(), keySize());
        typename V::Encryption mod(enc, iv());

        CryptoPP::StreamTransformationFilter str(mod, new CryptoPP::StringSink(cipher));
        str.Put(reinterpret_cast<const byte*>(plain.c_str()), plain.length());
        str.MessageEnd();
    }

    void Decrypt(std::istream& i, std::ostream& o) {
        decryption_traits<T, V>::CipherDecriptor dec(key(), keySize());
        decryption_traits<T, V>::ModDecriptor mod(dec, iv());

        CryptoPP::FileSource(i, true,
            new CryptoPP::StreamTransformationFilter(mod,
                new CryptoPP::FileSink(o)
            )
        );
    }

    void Decrypt(const std::string& cipher, std::string& plain) {
        decryption_traits<T, V>::CipherDecriptor dec(key(), keySize());
        decryption_traits<T, V>::ModDecriptor mod(dec, iv());

        CryptoPP::StreamTransformationFilter str(mod, new CryptoPP::StringSink(plain));
        str.Put(reinterpret_cast<const byte*>(cipher.c_str()), cipher.size());
        str.MessageEnd();
    }

private:
    CryptoPP::SecByteBlock _key;
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
