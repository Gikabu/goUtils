package utils

import (
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"strings"
)

func B64Encode(data []byte) string  {
	sEnc := b64.StdEncoding.EncodeToString(data)
	return sEnc
}

func B64Decode(sEnc string) []byte {
	decodeString, _ := b64.StdEncoding.DecodeString(sEnc)
	return decodeString
}

func GenerateScryptToken(uniqueId string, publicKey string) (string, error) {
	var pk [32]byte
	copy(pk[:], B64Decode(publicKey))
	var out []byte

	id := []byte(uniqueId)
	sealed, err := box.SealAnonymous(out, id, &pk, rand.Reader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s#%s", B64Encode(id), B64Encode(sealed)), nil
}

func GetScryptTokenID(token string) string {
	id := strings.Split(token, "#")[0]
	return string(B64Decode(id))
}

func ValidateScryptToken(token string, publicKey string, privateKey string) (bool, error) {
	subs := strings.Split(token, "#")
	if len(subs) < 2 {
		return false, errors.New("malformed scrypt token")
	}
	idPart := subs[0]
	cipherPart := subs[1]
	uniqueId := string(B64Decode(idPart))
	sealed := B64Decode(cipherPart)

	var pk [32]byte
	copy(pk[:], B64Decode(publicKey))
	var secret [32]byte
	copy(secret[:], B64Decode(privateKey))

	if byteSize(idPart) != (byteSize(cipherPart)-box.AnonymousOverhead) {
		return false, errors.New("invalid scrypt token length")
	}

	messageData, ok := box.OpenAnonymous(nil, sealed, &pk, &secret)
	if !ok {
		return false, errors.New("token decryption failed")
	}

	if string(messageData) != uniqueId {
		return false, errors.New("invalid scrypt token")
	}

	return true, nil
}

func byteSize(b64String string) uint64 {
	return uint64((len(b64String) * 6) / 8)
}