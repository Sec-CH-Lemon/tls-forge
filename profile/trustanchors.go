package profile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	rand "math/rand/v2"
	"slices"
	"sort"
	"sync"
)

// Chrome 154 and later send their trust-anchor IDs sorted by their bytes, as
// Chromium's EncodeTlsRequestedTrustAnchorIDList sorts them: every capture of
// 154 and 155, three platforms each, holds them so, and so did five fresh
// processes of Chrome 155.0.8059.80, headed and headless. An older Chrome kept
// them in a hash set, their order stable for one process and drawn anew for
// the next: the captures of 152 and of 153 on three machines hold three orders
// each. So a capture in byte order goes out as it is, and any other in one
// order drawn for its ID set, which every client in this process agrees on
// while the next process draws its own.
var processTrustAnchors = newTrustAnchorPayloads(rand.Shuffle)

type trustAnchorPayloads struct {
	mu      sync.Mutex
	bySet   map[string][]byte
	shuffle func(int, func(int, int))
}

func newTrustAnchorPayloads(shuffle func(int, func(int, int))) *trustAnchorPayloads {
	return &trustAnchorPayloads{bySet: make(map[string][]byte), shuffle: shuffle}
}

func (c *trustAnchorPayloads) payload(captured []byte) ([]byte, error) {
	records, err := splitTrustAnchors(captured)
	if err != nil {
		return nil, err
	}
	if inByteOrder(records) {
		// The browser sorts them, so they went out so every time.
		return append([]byte(nil), captured...), nil
	}

	// Each record includes its uint8 length, so their concatenation is an
	// unambiguous cache key. Sorting makes two captures of the same set share the
	// process-wide order even when their browser processes used different ones.
	sort.Slice(records, func(i, j int) bool { return bytes.Compare(records[i], records[j]) < 0 })
	key := string(bytes.Join(records, nil))

	c.mu.Lock()
	defer c.mu.Unlock()
	if payload, ok := c.bySet[key]; ok {
		return append([]byte(nil), payload...), nil
	}

	c.shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
	payload := joinTrustAnchors(records)
	c.bySet[key] = payload
	return append([]byte(nil), payload...), nil
}

// inByteOrder reports records whose IDs are sorted by their bytes. Chromium
// sorts the IDs themselves, so the length each record leads with takes no part:
// a shorter ID sorts by its bytes, not ahead of every longer one.
func inByteOrder(records [][]byte) bool {
	return slices.IsSortedFunc(records, func(a, b []byte) int { return bytes.Compare(a[1:], b[1:]) })
}

func splitTrustAnchors(payload []byte) ([][]byte, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("payload is shorter than its length field")
	}
	list := payload[2:]
	if int(binary.BigEndian.Uint16(payload[:2])) != len(list) {
		return nil, fmt.Errorf("length field does not match the list")
	}

	var records [][]byte
	for offset := 0; offset < len(list); {
		length := int(list[offset])
		if length == 0 {
			return nil, fmt.Errorf("anchor at offset %d is empty", offset)
		}
		end := offset + 1 + length
		if end > len(list) {
			return nil, fmt.Errorf("anchor at offset %d runs past the list", offset)
		}
		records = append(records, append([]byte(nil), list[offset:end]...))
		offset = end
	}
	return records, nil
}

func joinTrustAnchors(records [][]byte) []byte {
	size := 0
	for _, record := range records {
		size += len(record)
	}
	payload := make([]byte, 2, 2+size)
	binary.BigEndian.PutUint16(payload, uint16(size))
	for _, record := range records {
		payload = append(payload, record...)
	}
	return payload
}
