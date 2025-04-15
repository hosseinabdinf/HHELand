package utils

import (
	"os"
)

func CreateDir(path string) {
	err := os.MkdirAll(path, 0755) // owner can read, write and execute
	if err != nil && !os.IsExist(err) {
		HandleError(err)
	}
}
