package certstore

import (
	"testing"
)

func Test_ensureHostPort(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    string
		wantErr bool
	}{
		{"TestHostWithoutPort", "google.com", "google.com:443", false},
		{"TestHostWithPort", "www.champlain.edu:8443", "www.champlain.edu:8443", false},
		{"TestEmptyAddr", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ensureHostPort(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ensureHostPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ensureHostPort() got = %v, want %v", got, tt.want)
			}
		})
	}
}
