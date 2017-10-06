package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
	"unicode/utf8"
)

type Corpus map[rune]float64

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

func buildCorpus(text string) Corpus {
	totalChars := utf8.RuneCountInString(text)
	corpus := make(Corpus, totalChars)

	for _, char := range text {
		corpus[char]++
	}

	for i := range corpus {
		corpus[i] = corpus[i] / float64(totalChars)
	}

	return corpus
}

func scoreTextWithCorpus(text string, corpus Corpus) float64 {
	var score float64
	for _, char := range text {
		score += corpus[char]
	}

	return score / float64(utf8.RuneCountInString(text))
}

func singleXOR(in []byte, key byte) []byte {
	res := make([]byte, len(in))

	for i := range in {
		res[i] = in[i] ^ key
	}

	return res
}

func findSingleXORKey(in []byte, corpus Corpus) (res []byte, key byte, score float64) {
	for char := range corpus {
		out := singleXOR(in, byte(char))
		s := scoreTextWithCorpus(string(out), corpus)

		if s > score {
			res = out
			score = s
			key = byte(char)
		}
	}

	return
}

func repeatingXOR(in, key []byte) []byte {
	res := make([]byte, len(in))

	for i := range in {
		res[i] = in[i] ^ key[i%len(key)]
	}

	return res
}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("Inputs must be the same length")
	}

	var count int
	for i := range a {
		count += bits.OnesCount8(a[i] ^ b[i])
	}

	return count
}

func findRepeatingXORKeySize(in []byte) int {
	bestScore := math.MaxFloat64
	var res int

	for keyLen := 2; keyLen <= (len(in)/4/2 - 1); keyLen++ {
		a, b := in[:keyLen*4], in[keyLen*4:keyLen*4*2]
		score := float64(hammingDistance(a, b)) / float64(keyLen)

		if score < bestScore {
			bestScore = score
			res = keyLen
		}
	}

	return res
}

func findRepeatingXORKey(in []byte, corpus Corpus) []byte {
	keySize := findRepeatingXORKeySize(in)
	key := make([]byte, keySize)

	column := make([]byte, len(in)/keySize)

	for col := 0; col < keySize; col++ {
		for row := range column {
			if row*keySize+col > len(in) {
				continue
			}

			column[row] = in[row*keySize+col]
		}
    _, k, _ := findSingleXORKey(column, corpus)
    key[col] = k
	}

	return key
}
