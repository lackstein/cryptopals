package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
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
