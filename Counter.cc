#include "Counter.hh"

Counter::Counter(const wByte *nonce, wU32 size, wSize begin)
{
    if (size >= COUNTER_BLOCK_SIZE) {
        // error handler
    }
    memcpy(this->counter, nonce, size);

    this->counter[8]  |= (begin >> 56) & 0xff;
    this->counter[9]  |= (begin >> 48) & 0xff;
    this->counter[10] |= (begin >> 40) & 0xff;
    this->counter[11] |= (begin >> 32) & 0xff;
    this->counter[12] |= (begin >> 24) & 0xff;
    this->counter[13] |= (begin >> 16) & 0xff;
    this->counter[14] |= (begin >> 8)  & 0xff;
    this->counter[15] |= begin         & 0xff;
}

Counter::Counter(const char *nonce, wU32 size, wSize begin)
: Counter(reinterpret_cast<const wByte *>(nonce), size, begin)
{

}

Counter::Counter(std::string nonce, wSize begin)
: Counter(nonce.c_str(), nonce.size(), begin)
{

}

wByte *Counter::get() noexcept
{
    return this->counter;
}

void Counter::clean() noexcept
{
    memory_zero(this->counter, sizeof(counter));
}

void Counter::step_up() noexcept
{
    for (wI32 i = (COUNTER_BLOCK_SIZE - 1); i >= 0; --i) {
        if (*(this->counter + i) != 0xff) {
            ++(*(this->counter + i));
            break;
        }
        *(this->counter + i) = 0x00;
    }
}