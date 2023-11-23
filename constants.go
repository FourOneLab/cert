package main

const (
	PEM_TYPE_CERTIFICATE         = "CERTIFICATE"
	PEM_TYPE_CERTIFICATE_REQUEST = "CERTIFICATE REQUEST"
	PEM_TYPE_RSA_PRIVATE_KEY     = "RSA PRIVATE KEY"

	// file name
	CaCert     = "ca_cert.pem"
	ServerCert = "server_cert.pem"
	ServerKey  = "server_key.pem"
	ClientCert = "client_cert.pem"
	ClientKey  = "client_key.pem"

	defaultTLSPath          = "./"
	defaultPrefix           = "default"
	defaultCACommonName     = "default-CA"
	defaultServerCommonName = "default-server"
	defaultClientCommonName = "default-client"

	DefaultLengthForRSA = 2048
)
