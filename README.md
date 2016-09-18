# Simple security library

## Easy to use wrapper on top of cryptopp

```c++

Crypto::BlockCipher<Crypto::AES, Crypto::CBC> aes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

std::fstream temp;
temp.open("test.bin", std::ios::out | std::ios::binary);

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


```
