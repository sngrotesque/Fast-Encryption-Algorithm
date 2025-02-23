#pragma once

#include <malloc.h>

#include <cstring>
#include <cstdint>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef _MSC_VER
#   include <cstdbool>
#endif

typedef uint8_t  wByte,  w_byte;  // 字节类型

typedef int16_t  wS16,   w_s16;   // 16位带符号整数
typedef int16_t  wI16,   w_i16;   // 16位带符号整数
typedef uint16_t wU16,   w_u16;   // 16位无符号整数

typedef int32_t  wS32,   w_s32;   // 32位带符号整数
typedef int32_t  wI32,   w_i32;   // 32位带符号整数
typedef uint32_t wU32,   w_u32;   // 32位无符号整数

typedef int64_t  wI64,   w_i64;   // 64位带符号整数
typedef int64_t  wS64,   w_s64;   // 64位带符号整数
typedef uint64_t wU64,   w_u64;   // 64位无符号整数

#ifdef _MSC_VER
typedef int64_t ssize_t;
#endif

typedef ssize_t  wSSize, w_long,  wLong,  w_ssize; // 带符号长整数
typedef size_t   wSize,  w_ulong, wULong, w_size;  // 无符号长整数

#ifndef LIBWUK_API
#  ifdef WUK_EXPORTS
#    ifdef _WIN32
#      define LIBWUK_API     __declspec(dllexport)
#    elif defined(__ELF__) || defined(__linux)
#      define LIBWUK_API     __attribute__((visibility("protected")))
#    else
#      define LIBWUK_API     __attribute__((visibility("default")))
#    endif
#  else
#    ifdef _WIN32
#      define LIBWUK_API     __declspec(dllimport)
#    else
#      define LIBWUK_API     __attribute__((visibility("default")))
#    endif
#  endif
#endif

LIBWUK_API void memory_zero(void *p, wSize n);
LIBWUK_API void memory_secure(void *p, wSize n);
