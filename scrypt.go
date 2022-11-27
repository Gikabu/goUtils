package utils

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"strings"
	"time"
)

type TokenPayload struct {
	ID string `json:"id"`
	Type string `json:"type"`
	Subject string `json:"subject"`
	TargetID string `json:"target_id"`
	Expiry time.Time `json:"expiry"`
}

func B64Encode(data []byte) string  {
	sEnc := b64.StdEncoding.EncodeToString(data)
	return sEnc
}

func B64Decode(sEnc string) []byte {
	decodeString, _ := b64.StdEncoding.DecodeString(sEnc)
	return decodeString
}

func GenerateScryptToken(payload TokenPayload, publicKey string) (string, error) {
	var pk [32]byte
	copy(pk[:], B64Decode(publicKey))
	var out []byte

	id := []byte(payload.ID)
	payloadBytes, err := json.Marshal(payload)
	sealed, err := box.SealAnonymous(out, payloadBytes, &pk, rand.Reader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s#%s", B64Encode(id), B64Encode(sealed)), nil
}

func GetScryptTokenID(token string) string {
	id := strings.Split(token, "#")[0]
	return string(B64Decode(id))
}

func ValidateScryptToken(token string, publicKey string, privateKey string) (*TokenPayload, error) {
	subs := strings.Split(token, "#")
	if len(subs) < 2 {
		return nil, errors.New("malformed scrypt token")
	}
	idPart := subs[0]
	cipherPart := subs[1]
	id := string(B64Decode(idPart))
	sealed := B64Decode(cipherPart)

	var pk [32]byte
	copy(pk[:], B64Decode(publicKey))
	var secret [32]byte
	copy(secret[:], B64Decode(privateKey))

	if byteSize(idPart) != (byteSize(cipherPart)-box.AnonymousOverhead) {
		return nil, errors.New("invalid scrypt token length")
	}

	payloadBytes, ok := box.OpenAnonymous(nil, sealed, &pk, &secret)
	if !ok {
		return nil, errors.New("token decryption failed")
	}

	payload := new(TokenPayload)
	err := json.Unmarshal(payloadBytes, payload)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("invalid scrypt token, %s", err.Error()))
	}

	if payload.ID != id {
		return nil, errors.New("invalid scrypt token")
	}

	return payload, nil
}

func byteSize(b64String string) uint64 {
	return uint64((len(b64String) * 6) / 8)
}