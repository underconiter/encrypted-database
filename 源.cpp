/*
#include <aes.h>  
#include <cryptopp/Hex.h>      // StreamTransformationFilter  
#include <cryptopp/modes.h>    // CFB_Mode  
#include <iostream>             //std:cerr    
#include <sstream>              //std::stringstream    
#include <string>  

using namespace std;
using namespace CryptoPP;
#pragma comment( lib, "cryptlib.lib" )  


std::string CFB_AESEncryptStr(std::string sKey, std::string sIV, const char* plainText)
{
    std::string outstr;

    //填key    
    SecByteBlock key(AES::MAX_KEYLENGTH);
    memset(key, 0x30, key.size());
    sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

    //填iv    
    byte iv[AES::BLOCKSIZE];
    memset(iv, 0x30, AES::BLOCKSIZE);
    sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

    AES::Encryption aesEncryption((byte*)key, AES::MAX_KEYLENGTH);

    CFB_Mode_ExternalCipher::Encryption cfbEncryption(aesEncryption, iv);

    StreamTransformationFilter cfbEncryptor(cfbEncryption, new HexEncoder(new StringSink(outstr)));
    cfbEncryptor.Put((byte*)plainText, strlen(plainText));
    cfbEncryptor.MessageEnd();

    return outstr;
}


std::string CFB_AESDecryptStr(std::string sKey, std::string sIV, const char* cipherText)
{
    std::string outstr;

    //填key    
    SecByteBlock key(AES::MAX_KEYLENGTH);
    memset(key, 0x30, key.size());
    sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

    //填iv    
    byte iv[AES::BLOCKSIZE];
    memset(iv, 0x30, AES::BLOCKSIZE);
    sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

    CFB_Mode<AES >::Decryption cfbDecryption((byte*)key, AES::MAX_KEYLENGTH, iv);

    HexDecoder decryptor(new StreamTransformationFilter(cfbDecryption, new StringSink(outstr)));
    decryptor.Put((byte*)cipherText, strlen(cipherText));
    decryptor.MessageEnd();

    return outstr;
}



int main()
{
    string plainText = "Hello Crypto++! This is my first Crypto++ program.";
    string aesKey = "0123456789ABCDEF0123456789ABCDEF";//256bits, also can be 128 bits or 192bits  
    string aesIV = "ABCDEF0123456789";//128 bits  
    string cipherText, decryptedText;

    cipherText = CFB_AESEncryptStr(aesKey, aesIV, plainText.c_str());//加密¨¹  
    decryptedText = CFB_AESDecryptStr(aesKey, aesIV, cipherText.c_str());//解密¨¹  

    cout << "Crypto++ AES-256 CFB模式加密测试?" << endl;
    cout << "加密用密钥:" << aesKey << endl;
    cout << "密钥长度:" << AES::MAX_KEYLENGTH * 8 << "bits" << endl;
    cout << "CFB模式所需的IV:" << aesIV << endl;
    cout << endl;
    cout << "原文：" << plainText << endl;
    cout << "密文：" << cipherText << endl;
    cout << "恢复明文：" << decryptedText << endl;

    getchar();
    return 0;
}
*/