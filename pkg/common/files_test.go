package common

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
)

func TestResolvePath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err, "failed to get user home directory")

	tests := []struct {
		name     string
		filepath string
		want     string
	}{
		{"EmptyString", "", ""},
		{"Dot", ".", "."},
		{"DotFile", "./tmp", "tmp"},
		{"DotDir", "./tmp/", "tmp/"},
		{"DoubleDot", "..", ".."},
		{"DoubleDotFile", "../tmp", "../tmp"},
		{"DoubleDotDir", "../tmp/", "../tmp/"},
		{"Root", "/", "/"},
		{"UserHomeDirAndFile", "~/file.db", path.Join(homeDir, "file.db")},
		{"AbsolutePathDir", "/home/tmp/", "/home/tmp/"},
		{"AbsolutePathFile", "/home/tmp/file", "/home/tmp/file"},
		{"RelativePathDir", "home/tmp/", "home/tmp/"},
		{"RelativePathFile", "home/tmp/file", "home/tmp/file"},
		{"SingleFile", "test", "test"},
		{"SingleDir", "test/", "test/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolvePath(tt.filepath)
			assert.NoError(t, err, "unexpected error while resolving path")
			if err != nil {
				return
			}
			assert.Equalf(t, tt.want, got, "ResolvePath(%v)", tt.filepath)
		})
	}
}
