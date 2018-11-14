package multihash

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
)

type SumTestCase struct {
	code   uint64
	length int
	input  string
	hex    string
}

var sumTestCases = []SumTestCase{
	{ID, 3, "foo", "0003666f6f"},
	{ID, -1, "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo", "0030666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f666f6f"},
	{SHA1, -1, "foo", "11140beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"},
	{SHA1, 10, "foo", "110a0beec7b5ea3f0fdbc95d"},
	{SHA2_256, -1, "foo", "12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"},
	{SHA2_256, 16, "foo", "12102c26b46b68ffc68ff99b453c1d304134"},
	{SHA2_512, -1, "foo", "1340f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"},
	{SHA2_512, 32, "foo", "1320f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc663832"},
	{SHA3, 32, "foo", "14204bca2b137edc580fe50a88983ef860ebaca36c857b1f492839d6d7392452a63c"},
	{SHA3_512, 16, "foo", "14104bca2b137edc580fe50a88983ef860eb"},
	{SHA3_512, -1, "foo", "14404bca2b137edc580fe50a88983ef860ebaca36c857b1f492839d6d7392452a63c82cbebc68e3b70a2a1480b4bb5d437a7cba6ecf9d89f9ff3ccd14cd6146ea7e7"},
	{SHA3_224, -1, "beep boop", "171c0da73a89549018df311c0a63250e008f7be357f93ba4e582aaea32b8"},
	{SHA3_224, 16, "beep boop", "17100da73a89549018df311c0a63250e008f"},
	{SHA3_256, -1, "beep boop", "1620828705da60284b39de02e3599d1f39e6c1df001f5dbf63c9ec2d2c91a95a427f"},
	{SHA3_256, 16, "beep boop", "1610828705da60284b39de02e3599d1f39e6"},
	{SHA3_384, -1, "beep boop", "153075a9cff1bcfbe8a7025aa225dd558fb002769d4bf3b67d2aaf180459172208bea989804aefccf060b583e629e5f41e8d"},
	{SHA3_384, 16, "beep boop", "151075a9cff1bcfbe8a7025aa225dd558fb0"},
	{DBL_SHA2_256, 32, "foo", "5620c7ade88fc7a21498a6a5e5c385e1f68bed822b72aa63c4a9a48a02c2466ee29e"},
	{BLAKE2B_MAX, -1, "foo", "c0e40240ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d"},
	{BLAKE2B_MAX, 64, "foo", "c0e40240ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d"},
	{BLAKE2B_MAX - 32, -1, "foo", "a0e40220b8fe9f7f6255a6fa08f668ab632a8d081ad87983c77cd274e48ce450f0b349fd"},
	{BLAKE2B_MAX - 32, 32, "foo", "a0e40220b8fe9f7f6255a6fa08f668ab632a8d081ad87983c77cd274e48ce450f0b349fd"},
	{BLAKE2B_MAX - 19, -1, "foo", "ade4022dca82ab956d5885e3f5db10cca94182f01a6ca2c47f9f4228497dcc9f4a0121c725468b852a71ec21fcbeb725df"},
	{BLAKE2B_MAX - 19, 45, "foo", "ade4022dca82ab956d5885e3f5db10cca94182f01a6ca2c47f9f4228497dcc9f4a0121c725468b852a71ec21fcbeb725df"},
	{BLAKE2B_MAX - 16, -1, "foo", "b0e40230e629ee880953d32c8877e479e3b4cb0a4c9d5805e2b34c675b5a5863c4ad7d64bb2a9b8257fac9d82d289b3d39eb9cc2"},
	{BLAKE2B_MAX - 16, 48, "foo", "b0e40230e629ee880953d32c8877e479e3b4cb0a4c9d5805e2b34c675b5a5863c4ad7d64bb2a9b8257fac9d82d289b3d39eb9cc2"},
	{BLAKE2B_MIN + 19, -1, "foo", "94e40214983ceba2afea8694cc933336b27b907f90c53a88"},
	{BLAKE2B_MIN + 19, 20, "foo", "94e40214983ceba2afea8694cc933336b27b907f90c53a88"},
	{BLAKE2B_MIN, -1, "foo", "81e4020152"},
	{BLAKE2B_MIN, 1, "foo", "81e4020152"},
	{BLAKE2S_MAX, 32, "foo", "e0e4022008d6cad88075de8f192db097573d0e829411cd91eb6ec65e8fc16c017edfdb74"},
	{MURMUR3, 4, "beep boop", "2204243ddb9e"},
	{KECCAK_224, -1, "beep boop", "1a1c2bd72cde2f75e523512999eb7639f17b699efe29bec342f5a0270896"},
	{KECCAK_256, 32, "foo", "1b2041b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d"},
	{KECCAK_384, -1, "beep boop", "1c300e2fcca40e861fc425a2503a65f4a4befab7be7f193e57654ca3713e85262b035e54d5ade93f9632b810ab88b04f7d84"},
	{KECCAK_512, -1, "beep boop", "1d40e161c54798f78eba3404ac5e7e12d27555b7b810e7fd0db3f25ffa0c785c438331b0fbb6156215f69edf403c642e5280f4521da9bd767296ec81f05100852e78"},
	{SHAKE_128, 32, "foo", "1820f84e95cb5fbd2038863ab27d3cdeac295ad2d4ab96ad1f4b070c0bf36078ef08"},
	{SHAKE_256, 64, "foo", "19401af97f7818a28edfdfce5ec66dbdc7e871813816d7d585fe1f12475ded5b6502b7723b74e2ee36f2651a10a8eaca72aa9148c3c761aaceac8f6d6cc64381ed39"},
}

func TestSum(t *testing.T) {

	for _, tc := range sumTestCases {

		m1, err := FromHexString(tc.hex)
		if err != nil {
			t.Error(err)
			continue
		}

		m2, err := Sum([]byte(tc.input), tc.code, tc.length)
		if err != nil {
			t.Error(tc.code, "sum failed.", err)
			continue
		}

		if m1 != m2 {
			t.Error(tc.code, Codes[tc.code], "sum failed.", m1, m2)
			t.Error(hex.EncodeToString(m2.Bytes()))
		}

		s1 := m1.HexString()
		if s1 != tc.hex {
			t.Error("hex strings not the same")
		}

		s2 := m1.B58String()
		m3, err := FromB58String(s2)
		if err != nil {
			t.Error("failed to decode b58")
		} else if m3 != m1 {
			t.Error("b58 failing bytes")
		} else if s2 != m3.B58String() {
			t.Error("b58 failing string")
		}
	}
}

func BenchmarkSum(b *testing.B) {
	tc := sumTestCases[0]
	for i := 0; i < b.N; i++ {
		Sum([]byte(tc.input), tc.code, tc.length)
	}
}

func BenchmarkBlake2B(b *testing.B) {
	sizes := []uint64{128, 129, 130, 255, 256, 257, 386, 512}
	for _, s := range sizes {
		func(si uint64) {
			b.Run(fmt.Sprintf("blake2b-%d", s), func(b *testing.B) {
				arr := []byte("test data for some hashing, this is broken")
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					m, err := Sum(arr, BLAKE2B_MIN+si/8-1, -1)
					if err != nil {
						b.Fatal(err)
					}
					runtime.KeepAlive(m)
				}
			})
		}(s)
	}
}

// Test that the identity hash function checks
// its `length` arguemnt for values that are
// different to its `data` length.
func TestSmallerLengthHashID(t *testing.T) {

	data := []byte("Identity hash input data.")
	dataLength := len(data)

	// Normal case: `length == len(data)`.
	_, err := sumID(data, dataLength)
	if err != nil {
		t.Fatal(err)
	}

	// Unconstrained length (-1): also allowed.
	_, err = sumID(data, -1)
	if err != nil {
		t.Fatal(err)
	}

	// Any other variation of those two scenarios should fail.
	for l := (dataLength - 1); l >= 0; l-- {
		_, err = sumID(data, l)
		if err == nil {
			t.Fatal(fmt.Sprintf("identity hash of length %d smaller than data length %d didn't fail",
				l, dataLength))
		}
	}
}
