package hashpass

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

type Hash struct {
	Name       string
	SaltLength int
	Stretch    int
}

type HashFunc (func() hash.Hash)

var DefaultHash = Hash{"sha256", 16, 10000}

var hashNameMap = map[string]HashFunc{
	"md5":    md5.New,
	"sha1":   sha1.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

func (h *Hash) Key(password string) string {
	passBytes := []byte(password)
	salt := h.salt()
	hashFunc := hashNameMap[h.Name]
	hashLength := hashFunc().Size()
	key := Pbkdf2(passBytes, salt, h.Stretch, hashLength, hashFunc)
	encodedSalt := encode(salt)
	encodedKey := encode(key)
	return fmt.Sprintf("%s$%d$%s$%s", h.Name, h.Stretch, encodedSalt, encodedKey)
}

func Key(password string) string {
	return DefaultHash.Key(password)
}

func Check(password string, target string) bool {
	params := strings.Split(target, "$")
	if len(params) != 4 {
		panic(fmt.Errorf("invalid target"))
	}
	stretch, err := strconv.Atoi(params[1])
	if err != nil {
		panic(fmt.Errorf("invalid target"))
	}
	salt := decode(params[2])
	keyStr := params[3]
	hashName := params[0]
	hashFunc := hashNameMap[hashName]
	hashLength := hashFunc().Size()
	passBytes := []byte(password)
	val := Pbkdf2(passBytes, salt, stretch, hashLength, hashFunc)
	valStr := encode(val)
	return valStr == keyStr
}

func (h *Hash) salt() []byte {
	buf := make([]byte, h.SaltLength)
	n, err := rand.Read(buf)
	if n != len(buf) || err != nil {
		panic(fmt.Errorf("salt"))
	}
	return buf
}

func decode(s string) []byte {
	pad := len(s) % 4
	if pad > 0 {
		s += strings.Repeat("=", pad)
	}
	val, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Errorf("decode failed"))
	}
	return val
}

func encode(s []byte) string {
	val := base64.StdEncoding.EncodeToString(s)
	return strings.TrimRight(val, "=")
}
