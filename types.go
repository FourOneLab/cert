package main

import (
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// CertOptions is cert option.
type CertOptions struct {
	Begin, End time.Time
	IsClient   bool
	DNSNames   []string

	// CA
	CAName         string
	CAOrganization []string

	// Cert
	CommonName string
}

// KeyPairArtifacts is cert struct
type KeyPairArtifacts struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

type SecretOptions struct {
	Name         string
	Namespace    string
	CertPrefix   string
	CertDuration time.Duration
}
