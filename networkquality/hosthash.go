// Copyright LLVM contributors. Derived from libc++ __functional/hash.h.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Algorithm constants define the hash primitive, not browser profile defaults.

package networkquality

import (
	"encoding/binary"
	"math/bits"
)

const (
	cityK0 uint64 = 0xc3a5c85c97cb3127
	cityK1 uint64 = 0xb492b66fbe98f273
	cityK2 uint64 = 0x9ae16a3b2f90404f
	cityK3 uint64 = 0xc949d7c7509e6557
)

func cityRotate(v uint64, n int) uint64 { return bits.RotateLeft64(v, -n) }
func cityMix(v uint64) uint64           { return v ^ (v >> 47) }
func cityHash16(u, v uint64) uint64 {
	const mul uint64 = 0x9ddfea08eb382d69
	a := (u ^ v) * mul
	a ^= a >> 47
	b := (v ^ a) * mul
	b ^= b >> 47
	return b * mul
}
func cityWeak(s []byte, a, b uint64) (uint64, uint64) {
	w, x, y, z := binary.LittleEndian.Uint64(s), binary.LittleEndian.Uint64(s[8:]), binary.LittleEndian.Uint64(s[16:]), binary.LittleEndian.Uint64(s[24:])
	a += w
	b = cityRotate(b+a+z, 21)
	c := a
	a += x + y
	b += cityRotate(a, 44)
	return a + z, b + c
}

// LibcxxHash64 hashes the original host bytes with the supported little-endian
// libc++64 primitive. fixed selects its explicit widened4..8-byte ABI variant;
// the caller's policy selects the variant rather than the host Go architecture.
func LibcxxHash64(host string, fixed bool) uint64 {
	s := []byte(host)
	n := len(s)
	length := uint64(n)
	if n <= 16 {
		if n > 8 {
			a, b := binary.LittleEndian.Uint64(s), binary.LittleEndian.Uint64(s[n-8:])
			return cityHash16(a, cityRotate(b+length, n)) ^ b
		}
		if n >= 4 {
			a, b := binary.LittleEndian.Uint32(s), binary.LittleEndian.Uint32(s[n-4:])
			shift := uint64(a << 3)
			if fixed {
				shift = uint64(a) << 3
			}
			return cityHash16(length+shift, uint64(b))
		}
		if n > 0 {
			a, b, c := uint64(s[0]), uint64(s[n>>1]), uint64(s[n-1])
			y, z := a+(b<<8), length+(c<<2)
			return cityMix(y*cityK2^z*cityK3) * cityK2
		}
		return cityK2
	}
	if n <= 32 {
		a, b := binary.LittleEndian.Uint64(s)*cityK1, binary.LittleEndian.Uint64(s[8:])
		c, d := binary.LittleEndian.Uint64(s[n-8:])*cityK2, binary.LittleEndian.Uint64(s[n-16:])*cityK0
		return cityHash16(cityRotate(a-b, 43)+cityRotate(c, 30)+d, a+cityRotate(b^cityK3, 20)-c+length)
	}
	if n <= 64 {
		z := binary.LittleEndian.Uint64(s[24:])
		a := binary.LittleEndian.Uint64(s) + (length+binary.LittleEndian.Uint64(s[n-16:]))*cityK0
		b, c := cityRotate(a+z, 52), cityRotate(a, 37)
		a += binary.LittleEndian.Uint64(s[8:])
		c += cityRotate(a, 7)
		a += binary.LittleEndian.Uint64(s[16:])
		vf, vs := a+z, b+cityRotate(a, 31)+c
		a = binary.LittleEndian.Uint64(s[16:]) + binary.LittleEndian.Uint64(s[n-32:])
		z += binary.LittleEndian.Uint64(s[n-8:])
		b, c = cityRotate(a+z, 52), cityRotate(a, 37)
		a += binary.LittleEndian.Uint64(s[n-24:])
		c += cityRotate(a, 7)
		a += binary.LittleEndian.Uint64(s[n-16:])
		wf, ws := a+z, b+cityRotate(a, 31)+c
		r := cityMix((vf+ws)*cityK2 + (wf+vs)*cityK0)
		return cityMix(r*cityK0+vs) * cityK2
	}
	x := binary.LittleEndian.Uint64(s[n-40:])
	y := binary.LittleEndian.Uint64(s[n-16:]) + binary.LittleEndian.Uint64(s[n-56:])
	z := cityHash16(binary.LittleEndian.Uint64(s[n-48:])+length, binary.LittleEndian.Uint64(s[n-24:]))
	v0, v1 := cityWeak(s[n-64:], length, z)
	w0, w1 := cityWeak(s[n-32:], y+cityK1, x)
	x = x*cityK1 + binary.LittleEndian.Uint64(s)
	remaining := (n - 1) &^ 63
	for {
		x = cityRotate(x+y+v0+binary.LittleEndian.Uint64(s[8:]), 37) * cityK1
		y = cityRotate(y+v1+binary.LittleEndian.Uint64(s[48:]), 42) * cityK1
		x ^= w1
		y += v0 + binary.LittleEndian.Uint64(s[40:])
		z = cityRotate(z+w0, 33) * cityK1
		v0, v1 = cityWeak(s, v1*cityK1, x+w0)
		w0, w1 = cityWeak(s[32:], z+w1, y+binary.LittleEndian.Uint64(s[16:]))
		z, x = x, z
		s = s[64:]
		remaining -= 64
		if remaining == 0 {
			break
		}
	}
	return cityHash16(cityHash16(v0, w0)+cityMix(y)*cityK1+z, cityHash16(v1, w1)+x)
}
