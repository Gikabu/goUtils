package utils

import (
	"os"
)

func GetFileLength(filepath string) int64 {
	fi, err := os.Stat(filepath)
	if err != nil {
		return 0
	}
	return fi.Size()
}