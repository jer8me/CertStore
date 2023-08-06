package certstore

const (
	certFileFlag    = "cert-file"
	privKeyFileFlag = "priv-key-file"
	passwordFlag    = "password"
)

var certificateId int64
var certificateFile string
var privateKeyFile string
var password string
