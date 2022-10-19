package goUtils

import (
	"crypto/rand"
	"strconv"
	"time"
)

func randomCode(length int) string {
	var chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	ll := len(chars)
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		var nano = strconv.FormatInt(time.Now().UnixNano(), 10)
		if length > 12 {
			return nano
		}
		return nano[len(nano)-length:]
	}
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}

func randomNumber(length int) string {
	var chars = "0123456789"
	ll := len(chars)
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		var nano = strconv.FormatInt(time.Now().UnixNano(), 10)
		if length > 12 {
			return nano
		}
		return nano[len(nano)-length:]
	}
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}

func randomString(length int) string {
	var chars = "ABCDEF012GHIJKLM3456NOPQRST789UVWXYZ"
	ll := len(chars)
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return chars[len(chars)-length:]
	}
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}

func randomStringAlphabet(length int) string {
	var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ll := len(chars)
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return chars[len(chars)-length:]
	}
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}
