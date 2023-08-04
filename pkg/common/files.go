package common

import (
	"fmt"
	"os"
	"path"
	"strings"
)

func ResolvePath(filepath string) (string, error) {
	var found bool
	if filepath, found = strings.CutPrefix(filepath, "~"); found {
		// Path starts with a tilde, replace with the user's home directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		filepath = homeDir + "/" + filepath
	}
	dir, file := path.Split(filepath)
	if dir == "" {
		return file, nil
	}
	// Clean the directory part
	dir = path.Clean(dir)
	if file != "" {
		filepath = path.Join(dir, file)
	} else if dir == "/" {
		filepath = dir
	} else {
		filepath = dir + "/"
	}
	return filepath, nil
}
