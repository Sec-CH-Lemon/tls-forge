// Copyright LLVM contributors. Derived from libc++ __functional/hash.h.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <cstdint>
#include <cstring>
#include <utility>
#include <iostream>
#include <string>
#include <functional>
using std::size_t;
struct Pair {size_t first; size_t second;};
template<class T> T loadword(const void* p) {T v;std::memcpy(&v,p,sizeof(v));return v;}
template <class _Size, size_t = sizeof(_Size) * __CHAR_BIT__>
struct __murmur2_or_cityhash;

template <class _Size>
struct __murmur2_or_cityhash<_Size, 32> {
    _Size
  operator()(const void* __key, _Size __len) const {
    // murmur2
    const _Size __m             = 0x5bd1e995;
    const _Size __r             = 24;
    _Size __h                   = __len;
    const unsigned char* __data = static_cast<const unsigned char*>(__key);
    for (; __len >= 4; __data += 4, __len -= 4) {
      _Size __k = loadword<_Size>(__data);
      __k *= __m;
      __k ^= __k >> __r;
      __k *= __m;
      __h *= __m;
      __h ^= __k;
    }
    switch (__len) {
    case 3:
      __h ^= static_cast<_Size>(__data[2] << 16);
      [[__fallthrough__]];
    case 2:
      __h ^= static_cast<_Size>(__data[1] << 8);
      [[__fallthrough__]];
    case 1:
      __h ^= __data[0];
      __h *= __m;
    }
    __h ^= __h >> 13;
    __h *= __m;
    __h ^= __h >> 15;
    return __h;
  }
};

template <class _Size>
struct __murmur2_or_cityhash<_Size, 64> {
  // cityhash64
    _Size
  operator()(const void* __key, _Size __len) const {
    const char* __s = static_cast<const char*>(__key);
    if (__len <= 32) {
      if (__len <= 16) {
        return __hash_len_0_to_16(__s, __len);
      } else {
        return __hash_len_17_to_32(__s, __len);
      }
    } else if (__len <= 64) {
      return __hash_len_33_to_64(__s, __len);
    }

    // For strings over 64 bytes we hash the end first, and then as we
    // loop we keep 56 bytes of state: v, w, x, y, and z.
    _Size __x = loadword<_Size>(__s + __len - 40);
    _Size __y = loadword<_Size>(__s + __len - 16) + loadword<_Size>(__s + __len - 56);
    _Size __z =
        __hash_len_16(loadword<_Size>(__s + __len - 48) + __len, loadword<_Size>(__s + __len - 24));
    Pair __v = __weak_hash_len_32_with_seeds(__s + __len - 64, __len, __z);
    Pair __w = __weak_hash_len_32_with_seeds(__s + __len - 32, __y + __k1, __x);
    __x        = __x * __k1 + loadword<_Size>(__s);

    // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
    __len = (__len - 1) & ~static_cast<_Size>(63);
    do {
      __x = __rotate(__x + __y + __v.first + loadword<_Size>(__s + 8), 37) * __k1;
      __y = __rotate(__y + __v.second + loadword<_Size>(__s + 48), 42) * __k1;
      __x ^= __w.second;
      __y += __v.first + loadword<_Size>(__s + 40);
      __z = __rotate(__z + __w.first, 33) * __k1;
      __v = __weak_hash_len_32_with_seeds(__s, __v.second * __k1, __x + __w.first);
      __w = __weak_hash_len_32_with_seeds(__s + 32, __z + __w.second, __y + loadword<_Size>(__s + 16));
      std::swap(__z, __x);
      __s += 64;
      __len -= 64;
    } while (__len != 0);
    return __hash_len_16(__hash_len_16(__v.first, __w.first) + __shift_mix(__y) * __k1 + __z,
                         __hash_len_16(__v.second, __w.second) + __x);
  }

private:
  // Some primes between 2^63 and 2^64.
  static const _Size __k0 = 0xc3a5c85c97cb3127ULL;
  static const _Size __k1 = 0xb492b66fbe98f273ULL;
  static const _Size __k2 = 0x9ae16a3b2f90404fULL;
  static const _Size __k3 = 0xc949d7c7509e6557ULL;

   static _Size __rotate(_Size __val, int __shift) {
    return __shift == 0 ? __val : ((__val >> __shift) | (__val << (64 - __shift)));
  }

   static _Size __rotate_by_at_least_1(_Size __val, int __shift) {
    return (__val >> __shift) | (__val << (64 - __shift));
  }

   static _Size __shift_mix(_Size __val) { return __val ^ (__val >> 47); }

    static _Size __hash_len_16(_Size __u, _Size __v) {
    const _Size __mul = 0x9ddfea08eb382d69ULL;
    _Size __a         = (__u ^ __v) * __mul;
    __a ^= (__a >> 47);
    _Size __b = (__v ^ __a) * __mul;
    __b ^= (__b >> 47);
    __b *= __mul;
    return __b;
  }

    static _Size
  __hash_len_0_to_16(const char* __s, _Size __len) {
    if (__len > 8) {
      const _Size __a = loadword<_Size>(__s);
      const _Size __b = loadword<_Size>(__s + __len - 8);
      return __hash_len_16(__a, __rotate_by_at_least_1(__b + __len, __len)) ^ __b;
    }
    if (__len >= 4) {
      const uint32_t __a = loadword<uint32_t>(__s);
      const uint32_t __b = loadword<uint32_t>(__s + __len - 4);
#ifdef _LIBCPP_ABI_FIX_CITYHASH_IMPLEMENTATION
      return __hash_len_16(__len + (static_cast<_Size>(__a) << 3), __b);
#else
      return __hash_len_16(__len + (__a << 3), __b);
#endif
    }
    if (__len > 0) {
      const unsigned char __a = static_cast<unsigned char>(__s[0]);
      const unsigned char __b = static_cast<unsigned char>(__s[__len >> 1]);
      const unsigned char __c = static_cast<unsigned char>(__s[__len - 1]);
      const uint32_t __y      = static_cast<uint32_t>(__a) + (static_cast<uint32_t>(__b) << 8);
      const uint32_t __z      = __len + (static_cast<uint32_t>(__c) << 2);
      return __shift_mix(__y * __k2 ^ __z * __k3) * __k2;
    }
    return __k2;
  }

    static _Size
  __hash_len_17_to_32(const char* __s, _Size __len) {
    const _Size __a = loadword<_Size>(__s) * __k1;
    const _Size __b = loadword<_Size>(__s + 8);
    const _Size __c = loadword<_Size>(__s + __len - 8) * __k2;
    const _Size __d = loadword<_Size>(__s + __len - 16) * __k0;
    return __hash_len_16(
        __rotate(__a - __b, 43) + __rotate(__c, 30) + __d, __a + __rotate(__b ^ __k3, 20) - __c + __len);
  }

  // Return a 16-byte hash for 48 bytes.  Quick and dirty.
  // Callers do best to use "random-looking" values for a and b.
    static Pair
  __weak_hash_len_32_with_seeds(_Size __w, _Size __x, _Size __y, _Size __z, _Size __a, _Size __b) {
    __a += __w;
    __b             = __rotate(__b + __a + __z, 21);
    const _Size __c = __a;
    __a += __x;
    __a += __y;
    __b += __rotate(__a, 44);
    Pair __ret;
    __ret.first  = __a + __z;
    __ret.second = __b + __c;
    return __ret;
  }

  // Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
    static Pair
  __weak_hash_len_32_with_seeds(const char* __s, _Size __a, _Size __b) {
    return __weak_hash_len_32_with_seeds(
        loadword<_Size>(__s),
        loadword<_Size>(__s + 8),
        loadword<_Size>(__s + 16),
        loadword<_Size>(__s + 24),
        __a,
        __b);
  }

  // Return an 8-byte hash for 33 to 64 bytes.
    static _Size
  __hash_len_33_to_64(const char* __s, size_t __len) {
    _Size __z = loadword<_Size>(__s + 24);
    _Size __a = loadword<_Size>(__s) + (__len + loadword<_Size>(__s + __len - 16)) * __k0;
    _Size __b = __rotate(__a + __z, 52);
    _Size __c = __rotate(__a, 37);
    __a += loadword<_Size>(__s + 8);
    __c += __rotate(__a, 7);
    __a += loadword<_Size>(__s + 16);
    _Size __vf = __a + __z;
    _Size __vs = __b + __rotate(__a, 31) + __c;
    __a        = loadword<_Size>(__s + 16) + loadword<_Size>(__s + __len - 32);
    __z += loadword<_Size>(__s + __len - 8);
    __b = __rotate(__a + __z, 52);
    __c = __rotate(__a, 37);
    __a += loadword<_Size>(__s + __len - 24);
    __c += __rotate(__a, 7);
    __a += loadword<_Size>(__s + __len - 16);
    _Size __wf = __a + __z;
    _Size __ws = __b + __rotate(__a, 31) + __c;
    _Size __r  = __shift_mix((__vf + __ws) * __k2 + (__wf + __vs) * __k0);
    return __shift_mix(__r * __k0 + __vs) * __k2;
  }
};


int main(int argc,char**argv){for(int i=1;i<argc;i++){std::string s=argv[i];auto n=__murmur2_or_cityhash<size_t>()(s.data(),s.size());std::cout<<s<<" "<<n<<" "<<std::hash<std::string>{}(s)<<"\n";}}
