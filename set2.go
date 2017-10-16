package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	mathrand "math/rand"
)

func padPKCS7(in []byte, size int) []byte {
	if size >= 256 {
		panic("Can't pad to a blocksize greater than 255")
	}

	padLen := size - len(in)%size
	out := append(in, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	return out
}

func encryptCBC(src []byte, b cipher.Block, iv []byte) []byte {
	bs := b.BlockSize()

	if len(src)%bs != 0 {
		panic("Wrong input lengths")
	}
	if len(iv) != bs {
		panic("Wrong input lengths")
	}

	out := make([]byte, len(src))
	prev := iv

	for i := 0; i < len(src)/bs; i++ {
		copy(out[i*bs:], xor(src[i*bs:(i+1)*bs], prev))
		b.Encrypt(out[i*bs:], out[i*bs:])
		prev = out[i*bs : (i+1)*bs]
	}

	return out
}

func decryptCBC(src []byte, b cipher.Block, iv []byte) []byte {
	bs := b.BlockSize()

	if len(src)%bs != 0 {
		panic("Wrong input lengths")
	}
	if len(iv) != bs {
		panic("Wrong input lengths")
	}

	out := make([]byte, len(src))
	prev := iv
	buf := make([]byte, bs)

	for i := 0; i < len(src)/bs; i++ {
		b.Decrypt(buf, src[i*bs:])
		copy(out[i*bs:], xor(buf, prev))
		prev = src[i*bs : (i+1)*bs]
	}

	return out
}

func encryptECB(in []byte, b cipher.Block) []byte {
	if len(in)%b.BlockSize() != 0 {
		panic("Input length is not a multiple of the block size")
	}

	res := make([]byte, len(in))
	for i := 0; i < len(in); i += b.BlockSize() {
		b.Encrypt(res[i:], in[i:])
	}

	return res
}

func newECBCBCOracle() func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	b, _ := aes.NewCipher(key)

	return func(input []byte) []byte {
		prefix := make([]byte, 5+mathrand.Intn(5))
		rand.Read(prefix)
		suffix := make([]byte, 5+mathrand.Intn(5))
		rand.Read(suffix)

		msg := append(append(prefix, input...), suffix...)
		msg = padPKCS7(msg, 16)

		if mathrand.Intn(10)%2 == 0 {
			iv := make([]byte, 16)
			rand.Read(iv)
			return encryptCBC(msg, b, iv)
		} else {
			return encryptECB(msg, b)
		}
	}
}

func newECBSuffixOracle(secret []byte) func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)
	b, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
		msg := append(in, secret...)
		return encryptECB(padPKCS7(msg, 16), b)
	}
}

func recoverECBSuffix(oracle func([]byte) []byte) []byte {
	var blockSize int

	for bs := 1; bs < 100; bs++ {
		msg := bytes.Repeat([]byte{42}, 2*bs)
		msg = append(msg, 3)
		if detectECB(oracle(msg)[:bs*2], bs) {
			blockSize = bs
			break
		}
	}
	if blockSize == 0 {
		panic("Couldn't figure out byte size")
	}

	buildDict := func(known []byte) map[string]byte {
		dict := make(map[string]byte)
		msg := bytes.Repeat([]byte{42}, blockSize-1)
		msg = append(msg, known...)
		msg = append(msg, '?') // This byte will be replaced in the loop below
		msg = msg[len(msg)-blockSize:]

		for b := 0; b < 256; b++ {
			msg[blockSize-1] = byte(b)
			res := string(oracle(msg)[:blockSize])
			dict[res] = byte(b)
		}

		return dict
	}

	var plainText []byte
	for i := 0; i < len(oracle([]byte{})); i++ {
		dict := buildDict(plainText)
		msg := bytes.Repeat([]byte{42}, blockSize-(i%blockSize)-1)
		skip := i / blockSize * blockSize
		res := string(oracle(msg)[skip : skip+blockSize])
		plainText = append(plainText, dict[res])
	}

	return plainText
}
