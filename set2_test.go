package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge9(t *testing.T) {
	t.Logf("%x", padPKCS7([]byte("YELLOW SUBMARINE"), 20))
}

func TestChallenge10(t *testing.T) {
	msg := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	iv := make([]byte, 16)
	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	res := decryptCBC(encryptCBC(msg, b, iv), b, iv)
	if !bytes.Equal(res, msg) {
		t.Errorf("%q", res)
	}

	msg = decodeBase64(t, string(readFile(t, "_testdata/challenge10.txt")))
	t.Logf("%s", decryptCBC(msg, b, iv))
}

func TestChallenge11(t *testing.T) {
	oracle := newECBCBCOracle()
	payload := bytes.Repeat([]byte{42}, 16*3)
	cbc, ecb := 0, 0

	for i := 0; i < 1000; i++ {
		out := oracle(payload)
		if detectECB(out, 16) {
			ecb++
		} else {
			cbc++
		}
	}

	t.Log(ecb, cbc)
}

func TestChallenge12(t *testing.T) {
	secret := decodeBase64(t,
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
	oracle := newECBSuffixOracle(secret)
	decrypted := recoverECBSuffix(oracle)
	t.Logf("%s", decrypted)
}
