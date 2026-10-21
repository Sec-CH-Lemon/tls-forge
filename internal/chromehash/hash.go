// Copyright (C) 2024 Nicolas De Carli
// Based on rapidhash (BSD-2-Clause); see LICENSE.
// Package chromehash implements the deterministic ASCII header-name hash used
// by Blink's case-folding header map. It hashes lower-case UTF-16LE code units.
package chromehash

import (
	"encoding/binary"
	"math/bits"
)

func mix(a, b uint64) uint64 { hi, lo := bits.Mul64(a, b); return hi ^ lo }

// Hash returns Blink's 24-bit case-folding string hash for an ASCII name.
// Header-name validation is performed by the caller before this is reached.
func Hash(name string) uint32 {
	data := make([]byte, len(name)*2)
	for i, c := range []byte(name) {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		data[i*2] = c
	}
	const s0 uint64 = 0x2d358dccaa6c78a5
	const s1 uint64 = 0x8bb84b93962eacc9
	const s2 uint64 = 0x4b33a62ed433d4a3
	const initial uint64 = 0xbdd89aa982704029
	length := len(data)
	seed := initial ^ mix(initial^s0, s1) ^ uint64(length)
	read32 := func(i int) uint64 { return uint64(binary.LittleEndian.Uint32(data[i:])) }
	read64 := func(i int) uint64 { return binary.LittleEndian.Uint64(data[i:]) }
	var a, b uint64
	if length <= 16 {
		if length >= 4 {
			a = read32(0)<<32 | read32(length-4)
			offset := 0
			if length >= 8 {
				offset = 4
			}
			b = read32(offset)<<32 | read32(length-4-offset)
		} else if length > 0 {
			a = uint64(data[0])
		}
	} else {
		remaining, position := length, 0
		if remaining > 48 {
			one, two := seed, seed
			for {
				seed = mix(read64(position)^s0, read64(position+8)^seed)
				one = mix(read64(position+16)^s1, read64(position+24)^one)
				two = mix(read64(position+32)^s2, read64(position+40)^two)
				position += 48
				remaining -= 48
				if remaining < 48 {
					break
				}
			}
			seed ^= one ^ two
		}
		if remaining > 16 {
			seed = mix(read64(position)^s2, read64(position+8)^seed^s1)
			if remaining > 32 {
				seed = mix(read64(position+16)^s2, read64(position+24)^seed)
			}
		}
		a = read64(position + remaining - 16)
		b = read64(position + remaining - 8)
	}
	hi, lo := bits.Mul64(a^s1, b^seed)
	result := uint32(mix(lo^s0^uint64(length), hi^s1)) & 0xffffff
	if result == 0 {
		return 0x800000
	}
	return result
}
