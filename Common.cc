#include "Common.hh"

LIBWUK_API void memory_zero(void *p, wSize n)
{
    memset(p, 0x00, n);
}

LIBWUK_API void memory_secure(void *p, wSize n)
{
#       if defined(_WIN32)
    SecureZeroMemory(p, n);
#       elif defined(__linux)
    explicit_bzero(p, n);
#       endif
}
