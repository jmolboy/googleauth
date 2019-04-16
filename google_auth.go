package googleauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"github.com/skip2/go-qrcode"
	"net/url"
	"strings"
	"time"
)

type RandType int8

const (
	RandTypeAlphaNum RandType = 1
	RandTypeAlpha    RandType = 2
	RandTypeNum      RandType = 3
)


func RandSecret(strSize int, randType RandType) string {
	var dictionary string

	if randType == RandTypeAlphaNum {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == RandTypeAlpha {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == RandTypeNum {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	//使用base32算法
	return base32.StdEncoding.EncodeToString(bytes)
}

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func GetCode(secretKey string) (string, error) {
	value := toBytes(time.Now().Unix() / 30)
	secretKeyUpper := strings.ToUpper(secretKey)
	key, err := base32.StdEncoding.DecodeString(secretKeyUpper)
	if err != nil {
		return "", err
	}

	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000
	return string(pwd), nil
}

func QrCode(secret string, account string, issuer string, size int) ([]byte, error) {
	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		panic(err)
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)
	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	fmt.Printf("URL is %s\n", URL.String())
	return qrcode.Encode(URL.String(), qrcode.Medium, size)
}

func QrBase64(secret string, account string, issuer string, size int) (string, error) {
	codeSource, err := QrCode(secret, account, issuer, size)
	if err != nil {
		return "", err
	}
	base64Str := base64.StdEncoding.EncodeToString(codeSource)
	return "data:image/png;base64," + base64Str, nil
}
