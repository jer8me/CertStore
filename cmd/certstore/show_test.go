package main

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestShowCommand(t *testing.T) {
	certStore := newMockStore()
	err := LoadCertificates(certStore, []string{"champlain.crt", "github.crt"})
	require.NoError(t, err, "failed to load certificates")

	tests := []struct {
		name    string
		args    []string
		err     error
		wantOut string
	}{
		{
			"TestNoArguments",
			[]string{},
			errors.New("accepts 1 arg(s), received 0"),
			"",
		},
		{
			"TestTooManyArgument",
			[]string{"1", "2"},
			errors.New("accepts 1 arg(s), received 2"),
			"",
		},
		{
			"TestEmptyArgument",
			[]string{""},
			errors.New("invalid certificate ID"),
			"",
		},
		{
			"TestInvalidArgument",
			[]string{"xyz"},
			errors.New("invalid certificate ID"),
			"",
		},
		{
			"TestInvalidCertificateId",
			[]string{"10"},
			errors.New("certificate ID 10 does not exist"),
			"",
		},
		{
			"TestValidCertificateId",
			[]string{"1"},
			nil,
			"Subject: CN=*.champlain.edu,O=Champlain College,L=Burlington,ST=Vermont,C=US",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runTimeOut := &bytes.Buffer{}
			cmd := newShowCommand(certStore, runTimeOut)
			cmdOut := &bytes.Buffer{}
			cmd.SetOut(cmdOut)
			cmd.SetArgs(tt.args)
			err = cmd.Execute()
			if tt.err == nil {
				assert.NoError(t, err)
				assert.Nil(t, cmdOut.Bytes(), "unexpected command output")
			} else {
				assert.EqualError(t, err, tt.err.Error())
				assert.Equal(t, strings.TrimSpace(cmd.UsageString()), strings.TrimSpace(cmdOut.String()), "usage string does not match")
			}
			assert.Contains(t, runTimeOut.String(), tt.wantOut, "unexpected runtime output")
		})
	}
}
