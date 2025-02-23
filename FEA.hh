#pragma once
#include "Common.hh"
#include "Counter.hh"

constexpr wU32 WUK_FEA_KEYLEN = 32;
constexpr wU32 WUK_FEA_IVLEN  = 16;
constexpr wU32 WUK_FEA_BL     = 16; // FEA block length
constexpr wU32 WUK_FEA_NB     = 4;
constexpr wU32 WUK_FEA_NK     = 4;
constexpr wU32 WUK_FEA_NR     = 4;

enum class mode {
    ECB,  // Electronic Codebook
    CBC,  // Cipher block chaining
    CFB,  // Cipher feedback
    CTR   // Counter
};

/*
* This algorithm, when using any encryption mode, cannot be missing 
* the IV even if the data required for the corresponding mode is provided.
* 
* For example, in the case of using CTR mode, even if Nonce is provided,
* there cannot be no IV, because RoundKey is generated jointly
* by Key and IV through the keyExtension function.
* 
* If the IV is missing or the actual length of the incoming IV is not $(WUK_FEA_BL),
* the encryption result will become uncontrollable.
* 
* Unlike the AES algorithm, this algorithm requires the joint action of IV and Key
* to generate the key required for encryption/decryption.
* Therefore, even when using CTR mode, please add IV and ensure
* that its length is equal to $(WUK_FEA_BL).
* 
* Of course, when using CTR mode, you can also encrypt/decrypt normally
* without adding Nonce, but the security of the ciphertext is guaranteed by yourself.
*/
class LIBWUK_API FEA {
private:
    wByte iv[WUK_FEA_IVLEN];
    wByte roundKey[WUK_FEA_KEYLEN * WUK_FEA_NR];

    Counter counter;
    wU32 segmentSize;

private:
    void sub_bytes(wByte *block);
    void shift_bits(wByte *block);

    void inv_sub_bytes(wByte *block);
    void inv_shift_bits(wByte *block);

    void shift_rows(wByte *block);
    void inv_shift_rows(wByte *block);

    void xor_with_iv(wByte *block, wByte *iv);

    void cipher(wByte *p, wByte *roundKey);
    void inv_cipher(wByte *c, wByte *roundKey);

    void key_extension(const wByte *key, const wByte *iv);

    void ecb_encrypt(wByte *p);
    void ecb_decrypt(wByte *c);

    void cbc_encrypt(wByte *p, wSize n);
    void cbc_decrypt(wByte *c, wSize n);

    void ctr_xcrypt(wByte *d, wSize n);

    void cfb_encrypt(wByte *p, wSize n, wU32 segmentSize);
    void cfb_decrypt(wByte *c, wSize n, wU32 segmentSize);

public:
    FEA();
    FEA(const wByte *key, const wByte *iv,
        Counter counter = {},
        const wU32 segmentSize = 128);

public:
    void encrypt(wByte *content, wSize size, mode mode);
    void decrypt(wByte *content, wSize size, mode mode);

public:
    void set_counter(Counter counter);
    void set_segment_size(wU32 segment_size);
    const wByte *get_round_key() const;
};
