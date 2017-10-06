package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()

	res, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()

	res, err := base64.StdEncoding.DecodeString(s)
  if err != nil {
    t.Fatal(err)
  }

  return res
}

func corpusFromFile(fileName string) Corpus {
	text, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	return buildCorpus(string(text))
}

var corpus = corpusFromFile("_testdata/sherlock.txt")

func readFile(t *testing.T, fileName string) []byte {
	t.Helper()

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestChallenge1(t *testing.T) {
	res, err := hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Error("Wrong output:", res)
	}
}

func TestChallenge2(t *testing.T) {
	res := xor(decodeHex(t, "1c0111001f010100061a024b53535009181c"), decodeHex(t, "686974207468652062756c6c277320657965"))
	if !bytes.Equal(res, decodeHex(t, "746865206b696420646f6e277420706c6179")) {
		t.Errorf("Wrong output: %x", res)
	}
}

func TestChallenge3(t *testing.T) {
	res, _, _ := findSingleXORKey(decodeHex(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), corpus)
	t.Logf("%s", res)
}

func TestChallenge4(t *testing.T) {
	data := readFile(t, "_testdata/challenge4.txt")
	var bestScore float64
	var res string

	for _, line := range strings.Split(string(data), "\n") {
		out, _, score := findSingleXORKey(decodeHex(t, line), corpus)

		if score > bestScore {
			bestScore = score
			res = string(out)
		}
	}

	t.Logf("%v", res)
}

func TestChallenge5(t *testing.T) {
	in := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	expected := decodeHex(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	res := repeatingXOR([]byte(in), []byte("ICE"))
	if !bytes.Equal(res, expected) {
		t.Error("Wrong result. Got", res)
	}
}

func TestChallenge6(t *testing.T) {
	distance := hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if distance != 37 {
		t.Error("Wrong Hamming distance. Got", distance)
	}

  keySize := findRepeatingXORKeySize(decodeHex(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))
  if keySize != 3 {
    t.Error("Wrong key size. Got", keySize)
  }

  data := decodeBase64(t, string(readFile(t, "_testdata/challenge6.txt")))
  keySize2 := findRepeatingXORKeySize(data)
  t.Logf("Likely key size: %v", keySize2)
  key := findRepeatingXORKey(data, corpus)
  t.Logf("Likely key: %q", key)
  t.Logf("%s", repeatingXOR(data, key))
}
