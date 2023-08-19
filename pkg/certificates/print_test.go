package certificates_test

import (
	"bytes"
	"github.com/jer8me/CertStore/pkg/certificates"
	"github.com/jer8me/CertStore/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path"
	"strings"
	"testing"
)

func TestPrintHex(t *testing.T) {
	type args struct {
		b      []byte
		indent int
	}
	tests := []struct {
		name  string
		args  args
		wantW string
	}{
		{"TestEmptyByteSlice", args{nil, 4}, ""},
		{"TestSingleByte", args{[]byte{0}, 4}, "    00"},
		{"TestNoIndent", args{[]byte{15}, 0}, "0f"},
		{"TestMultiLine", args{[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, 2}, "  00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f\n  10:11:12:13:14"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			certificates.PrintHex(w, tt.args.b, tt.args.indent)
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("PrintHex() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestPrintCertificate(t *testing.T) {
	filename := path.Join("../../testdata", "champlain.crt")
	certs, privateKeys, err := certificates.ParsePEMFile(filename)
	require.NoError(t, err, "failed to parse certificate")
	assert.Nil(t, privateKeys, "unexpected private key found")
	assert.Len(t, certs, 1, "expected exactly one certificate")

	certificate := store.ToCertificate(certs[0])

	var sb strings.Builder
	certificates.PrintCertificate(&sb, certificate)
	assert.Len(t, sb.String(), 2504, "invalid certificate printed content")
}
