#include "FEA.hh"
#include <iostream>

/*
* Conventional compilation instructions:
* g++ -O3 -Wall test.cc Common.cc Counter.cc FEA_CBC.cc FEA_ECB.cc FEA_CTR.cc FEA_CFB.cc FEA.cc -o test.exe && test.exe
* 
* Dynamic library compilation instruction:
* g++ -O3 -Wall -DWUK_EXPORTS Common.cc Counter.cc FEA_CBC.cc FEA_ECB.cc FEA_CTR.cc FEA_CFB.cc FEA.cc -fPIC -shared -o libfea.dll
* 
* Link dynamic library compilation instruction:
* g++ -O3 -Wall test.cc -lfea -L. -o test.exe && test.exe
*/

void print_hex(const wByte *data, wSize len, wSize num, bool newline, bool tableChar)
{
    for(wSize i = 0; i < len; ++i) {
        if(tableChar && ((i) % num == 0)) {
            printf("\t");
        }

        printf("%02x", data[i]);

        if((i + 1) % num) {
            printf(" ");
        } else {
            printf("\n");
        }
    }
    if(newline)
        printf("\n");
}

wByte *pkcs7_pad(const wByte *data, wSize &length, wU32 blockSize)
{
    if(!data) {
        return nullptr;
    }
    wU32 padLen;
    wSize totalLen;

    padLen = blockSize - length % blockSize;
    totalLen = length + padLen;

    wByte *padded = reinterpret_cast<wByte *>(malloc(totalLen));
    memcpy(padded, data, length);
    memset(padded + length, padLen, padLen);

    length = totalLen;

    return padded;
}

wByte *pkcs7_unpad(const wByte *data, wSize &length)
{
    if(!data) {
        return nullptr;
    }
    wU32 padLen = data[length - 1];
    wSize unpaddedLen = length - padLen;

    wByte *unpadded = reinterpret_cast<wByte *>(malloc(unpaddedLen));
    memcpy(unpadded, data, unpaddedLen);

    length = unpaddedLen;

    return unpadded;
}

void vulnerability_testing()
{
    std::cout << "\x1b[91m" << "Weak key testing...\n" << "\x1b[0m";

    // Initialize to all 0 bytes (demonstrating the strength of
    // the round key generated with the weakest key and initial vector).
    wByte key[WUK_FEA_KEYLEN]{0xff};
    wByte iv[WUK_FEA_IVLEN]{};

    // Initialize plaintext to all 0 bytes.
    wByte content[WUK_FEA_BL]{};

    // Initialize encryption context.
    FEA fea(key, iv);

    // Print round key
    std::cout << "Round key:\n";
    print_hex(fea.get_round_key(), WUK_FEA_KEYLEN * WUK_FEA_NR, WUK_FEA_KEYLEN, true, true);

    // Print plaintext content.
    std::cout << "Plaintext:\n";
    print_hex(content, sizeof(content), 16, true, true);

    // Encryption
    fea.encrypt(content, sizeof(content), mode::ECB);

    // Print ciphertext content
    std::cout << "Ciphertext:\n";
    print_hex(content, sizeof(content), 16, true, true);

    // Decryption
    fea.decrypt(content, sizeof(content), mode::ECB);

    // Print plaintext content.
    std::cout << "Plaintext:\n";
    print_hex(content, sizeof(content), 16, true, true);
}

void encryption_test()
{
    std::cout << "\x1b[91m" << "Encryption testing...\n" << "\x1b[0m";

    // Initialize the key and initial vector.
    wByte iv[WUK_FEA_IVLEN] = {
        0xda, 0xa3, 0x22, 0x84, 0x68, 0x31, 0x4d, 0xe7,
        0x86, 0x37, 0x19, 0x04, 0xea, 0x3f, 0x10, 0x69
    };
    wByte key[WUK_FEA_KEYLEN] = {
        0xd3, 0x9e, 0x2a, 0x33, 0x69, 0x82, 0x51, 0xa3,
        0x60, 0x31, 0x3b, 0x65, 0xb7, 0xa0, 0x64, 0xad,
        0x87, 0x12, 0xd7, 0x8d, 0x1a, 0x45, 0x03, 0x36,
        0xe9, 0xf6, 0xcc, 0x5e, 0xc9, 0xfe, 0x4e, 0x8a
    };

    // Set a plain text content.
    char _p[] = {"Hello, world.\nI'm SN-Grotesque.\n"};
    wByte *content = reinterpret_cast<wByte *>(_p);
    wSize length = strlen(_p);

    // Initialize encryption context.
    Counter counter("this is test.", 123456);
    wU32 segment_size = 32; // Min: 8, Max: 128.
    FEA fea(key, iv, counter, segment_size);

    // Print plaintext content.
    wByte *padded = pkcs7_pad(content, length, WUK_FEA_BL);
    std::cout << "Plaintext(Padded):\n";
    print_hex(padded, length, 16, true, true);

    // Print round key
    std::cout << "Round key:\n";
    print_hex(fea.get_round_key(), WUK_FEA_KEYLEN * WUK_FEA_NR, WUK_FEA_KEYLEN, true, true);

    // Add four new blocks for encryption.
    wByte encryption_block[length * 4]{};
    for (wU32 i = 0; i < 4; ++i) {
        memcpy(encryption_block + length * i, padded, length);
    }
    wByte *encryption_block_ecb = encryption_block;
    wByte *encryption_block_cbc = encryption_block + length * 1;
    wByte *encryption_block_cfb = encryption_block + length * 2;
    wByte *encryption_block_ctr = encryption_block + length * 3;

    // Show the changes in ciphertext under different encryption modes.
    std::cout << "Ciphertext:\n";

    std::cout << "\x1b[96m" << "Current mode: ECB\n" << "\x1b[0m";
    for (wSize i = 0; i < length; i += WUK_FEA_BL) {
        fea.encrypt(encryption_block_ecb + i, length, mode::ECB);
    }
    print_hex(encryption_block_ecb, length, 16, true, true);

    std::cout << "\x1b[96m" << "Current mode: CBC\n" << "\x1b[0m";
    fea.encrypt(encryption_block_cbc, length, mode::CBC);
    print_hex(encryption_block_cbc, length, 16, true, true);

    std::cout << "\x1b[96m" << "Current mode: CFB\n" << "\x1b[0m";
    fea.encrypt(encryption_block_cfb, length, mode::CFB);
    print_hex(encryption_block_cfb, length, 16, true, true);

    std::cout << "\x1b[96m" << "Current mode: CTR\n" << "\x1b[0m";
    fea.encrypt(encryption_block_ctr, length, mode::CTR);
    print_hex(encryption_block_ctr, length, 16, true, true);
}

int main()
{
    encryption_test();

    // vulnerability_testing();

    return 0;
}
