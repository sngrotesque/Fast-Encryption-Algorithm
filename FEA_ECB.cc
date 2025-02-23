#include "FEA.hh"

void FEA::ecb_encrypt(wByte *p)
{
    this->cipher(p, this->roundKey);
}

void FEA::ecb_decrypt(wByte *c)
{
    this->inv_cipher(c, this->roundKey);
}
