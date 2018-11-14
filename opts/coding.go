package opts

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	base58 "github.com/mr-tron/base58/base58"
	mh "github.com/multiformats/go-multihash"
)

func Decode(encoding, digest string) (mh.Multihash, error) {
	switch encoding {
	case "raw":
		return mh.Cast([]byte(digest))
	case "hex":
		bts, err := hex.DecodeString(digest)
		if err != nil {
			return mh.Nil, err
		}
		return mh.Cast(bts)
	case "base58":
		bts, err := base58.Decode(digest)
		if err != nil {
			return mh.Nil, err
		}
		return mh.Cast(bts)
	case "base64":
		bts, err := base64.StdEncoding.DecodeString(digest)
		if err != nil {
			return mh.Nil, err
		}
		return mh.Cast(bts)
	default:
		return mh.Nil, fmt.Errorf("unknown encoding: %s", encoding)
	}
}

func Encode(encoding string, hash mh.Multihash) (string, error) {
	switch encoding {
	case "raw":
		return hash.Binary(), nil
	case "hex":
		return hex.EncodeToString(hash.Bytes()), nil
	case "base58":
		return base58.Encode(hash.Bytes()), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(hash.Bytes()), nil
	default:
		return "", fmt.Errorf("unknown encoding: %s", encoding)
	}
}
