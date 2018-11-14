package strbinary

import (
	"encoding/binary"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	testCases := []uint64{0, 1, 2, 127, 128, 129, 255, 256, 257, 1<<63 - 1}
	for _, tc := range testCases {
		buf := make([]byte, 16)
		binary.PutUvarint(buf, tc)
		v, l1 := Uvarint(string(buf))
		_, l2 := binary.Uvarint(buf)
		if tc != v {
			t.Errorf("roundtrip failed expected %d but got %d", tc, v)
		}
		if l1 != l2 {
			t.Errorf("length incorrect expected %d but got %d", l2, l1)
		}
	}
}

func TestLength(t *testing.T) {
	testCases := []uint64{0, 1, 2, 127, 128, 129, 255, 256, 257, 1<<63 - 1}
	for _, tc := range testCases {
		buf := make([]byte, 16)
		binary.PutUvarint(buf, tc)
		_, expected := binary.Uvarint(buf)
		actual := UvarintLen(string(buf))
		if expected != actual {
			t.Errorf("length incorrect expected %d but got %d", expected, actual)
		}
	}
}
