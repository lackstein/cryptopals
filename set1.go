package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

func hexToBase64(hexString string) (string, error) {
	res, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor: byte slices have different lengths")
	}

	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}

	return res
}
