package libhashx

import(
	"encoding/hex"
	"crypto/sha256"
	"math/rand"
)

func Hash(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

type LibHashX struct {
	Mnemonic []string
	Length int
}

func (this LibHashX) GenPriv() []string {
	c := 0
	key := ""
	for c < this.Length {
		c++
		key += this.Mnemonic[rand.Intn(len(this.Mnemonic))] + " "
	}
	key = key[:len(key)-1]
	return []string{Hash(key),key}
}

func (this LibHashX) GenPub(priv string) string {
	pub := priv + "PublicKeyStandardForHashXByXyte"
	return Hash(pub)
}

func (this LibHashX) SignData(data string,priv string) string {
	signature := data + priv
	return Hash(signature)
}

func (this LibHashX) VerifySign(sign string,data string,priv string) bool {
	signature := data + priv
	if Hash(signature) == sign {
		return true
	}
	return false
}

func (this LibHashX) VerifyPrivate(priv string,pub string) bool {
	key := Hash(priv + "PublicKeyStandardForHashXByXyte")
	if key == pub {
		return true
	}
	return false
}
