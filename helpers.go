package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	oidExtensionKeyUsage         = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage = []int{2, 5, 29, 37}
	oidExtensionBasicConstraints = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName   = []int{2, 5, 29, 17}
)

// CreateCertificateRequestConfiguration creates a certificate request configuration.
func CreateCertificateRequestConfiguration(name, ip string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Subject: pkix.Name{
			CommonName: name,
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidExtensionBasicConstraints,
				Critical: true,
				Value:    []byte("CA:FALSE"),
			},
			{
				Id:       oidExtensionKeyUsage,
				Critical: true,
				Value:    []byte("digitalSignature, keyEncipherment"),
			},
			{
				Id:       oidExtensionExtendedKeyUsage,
				Critical: true,
				Value:    []byte("serverAuth"),
			},
			{
				Id:       oidExtensionSubjectAltName,
				Critical: true,
				Value:    []byte(ip),
			},
		},
		DNSNames: []string{ip},
	}
}

// GeneratePrivateKey generates a new RSA private key with the default length 2048.
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, DefaultLengthForRSA)
}

// CreateCertificateRequestContent generates a CSR based on the provided template and private key.
func CreateCertificateRequestContent(template *x509.CertificateRequest, privateKey any) (csr []byte, err error) {
	return x509.CreateCertificateRequest(rand.Reader, template, privateKey)
}

func CreateCACert(opt CertOptions) (*KeyPairArtifacts, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   opt.CAName,
			Organization: opt.CAOrganization,
		},
		DNSNames:              opt.DNSNames,
		NotBefore:             opt.Begin,
		NotAfter:              opt.End,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// RSA 推荐密钥长度 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generating key, error: %v", err)
	}

	// template == parent ,so generate self-signed certificate
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to creating self-signed certificate, error: %v", err)
	}

	// encode certificate and private key
	certPEM, err := pemEncoding(der, PEM_TYPE_CERTIFICATE)
	if err != nil {
		return nil, err
	}

	keyPEM, err := pemKeyEncoding(privateKey)

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parsing certificate, error: %v", err)
	}
	return &KeyPairArtifacts{
		Cert:    cert,
		Key:     privateKey,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func CreateCertPEM(opt CertOptions, ca *KeyPairArtifacts) ([]byte, []byte, error) {
	sn, err := genSerialNum()
	if err != nil {
		return nil, nil, err
	}

	dnsNames := opt.DNSNames
	eks := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if opt.IsClient {
		eks = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		dnsNames = nil
	}

	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: opt.CommonName},
		DNSNames:              dnsNames,
		NotBefore:             opt.Begin,
		NotAfter:              opt.End,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           eks,
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generating key, error: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate, error: %v", err)
	}
	certPEM, err := pemEncoding(der, PEM_TYPE_CERTIFICATE)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encoding certificate, error: %v", err)
	}
	keyPEM, err := pemKeyEncoding(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encoding key, error: %v", err)
	}
	return certPEM, keyPEM, nil
}

func pemKeyEncoding(key *rsa.PrivateKey) ([]byte, error) {
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{Type: PEM_TYPE_RSA_PRIVATE_KEY, Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, fmt.Errorf("failed to encoding key, error: %v", err)
	}
	return keyBuf.Bytes(), nil
}

func pemEncoding(rawData []byte, requestType string) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := pem.Encode(buf, &pem.Block{Type: requestType, Bytes: rawData}); err != nil {
		return nil, fmt.Errorf("failed to encoding PEM, error: %v", err)
	}
	return buf.Bytes(), nil
}

func genSerialNum() (*big.Int, error) {
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialNumLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number, error: %v", err)
	}
	return serialNum, nil
}

func CreateSecretWithTLS(ctx context.Context, client kubernetes.Interface, opts SecretOptions) error {
	secret, err := client.CoreV1().Secrets(opts.Namespace).Get(ctx, opts.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err == nil {
		if _, ok := secret.Data[CaCert]; !ok {
			return errors.New("CA Certificate is not exist")
		}
		if _, ok := secret.Data[ServerCert]; !ok {
			return errors.New("Server Certificate is not exist")
		}
		if _, ok := secret.Data[ServerKey]; !ok {
			return errors.New("Server Private Key is not exist")
		}
		if _, ok := secret.Data[ClientCert]; !ok {
			return errors.New("Client Certificate is not exist")
		}
		if _, ok := secret.Data[ClientKey]; !ok {
			return errors.New("Client Private key is not exist")
		}
		return nil
	}

	c, err := generateCerts(opts.CertDuration)
	if err != nil {
		return err
	}

	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        opts.Name,
			Namespace:   opts.Namespace,
			Labels:      map[string]string{"": ""},
			Annotations: map[string]string{"": ""},
			Finalizers:  []string{},
		},
		Data: map[string][]byte{
			addPrefix(opts.CertPrefix, CaCert):     c.Kpa.CertPEM,
			addPrefix(opts.CertPrefix, ServerCert): c.ServerCert,
			addPrefix(opts.CertPrefix, ServerKey):  c.ServerKey,
			addPrefix(opts.CertPrefix, ClientCert): c.ClientCert,
			addPrefix(opts.CertPrefix, ClientKey):  c.ClientKey,
		},
	}

	_, err = client.CoreV1().Secrets(opts.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

func WriteCertsToFile(prefix string, certsDuration time.Duration) error {
	c, err := generateCerts(certsDuration)
	if err != nil {
		return err
	}

	caCertFile := filepath.Join(defaultTLSPath, addPrefix(prefix, CaCert))
	serverCertFile := filepath.Join(defaultTLSPath, addPrefix(prefix, ServerCert))
	serverKeyFile := filepath.Join(defaultTLSPath, addPrefix(prefix, ServerKey))
	clientCertFile := filepath.Join(defaultTLSPath, addPrefix(prefix, ClientCert))
	clientKeyFile := filepath.Join(defaultTLSPath, addPrefix(prefix, ClientKey))

	if err := WriteAndSyncFile(caCertFile, c.Kpa.CertPEM, os.FileMode(0644)); err != nil {
		return err
	}
	if err := WriteAndSyncFile(serverCertFile, c.Kpa.CertPEM, os.FileMode(0644)); err != nil {
		return err
	}
	if err := WriteAndSyncFile(serverKeyFile, c.Kpa.CertPEM, os.FileMode(0644)); err != nil {
		return err
	}
	if err := WriteAndSyncFile(clientCertFile, c.Kpa.CertPEM, os.FileMode(0644)); err != nil {
		return err
	}
	if err := WriteAndSyncFile(clientKeyFile, c.Kpa.CertPEM, os.FileMode(0644)); err != nil {
		return err
	}
	return nil
}

func WriteAndSyncFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	return err
}

type Certs struct {
	Kpa                                          *KeyPairArtifacts
	ServerCert, ServerKey, ClientCert, ClientKey []byte
}

func generateCerts(certDuration time.Duration) (*Certs, error) {
	begin := time.Now().Add(-time.Hour)
	end := begin.Add(certDuration)

	// CA
	caOpts := CertOptions{
		Begin:          begin,
		End:            end,
		DNSNames:       []string{defaultCACommonName},
		CAName:         defaultCACommonName,
		CAOrganization: []string{defaultCACommonName},
		CommonName:     defaultCACommonName,
	}
	kpa, err := CreateCACert(caOpts)
	if err != nil {
		return nil, err
	}

	// Server
	serverOpts := CertOptions{
		Begin:      begin,
		End:        end,
		DNSNames:   []string{defaultServerCommonName},
		CommonName: defaultServerCommonName,
	}
	serverCert, serverKey, err := CreateCertPEM(serverOpts, kpa)
	if err != nil {
		return nil, err
	}

	// Client
	clientOpts := CertOptions{
		Begin:      begin,
		End:        end,
		IsClient:   true,
		DNSNames:   []string{defaultClientCommonName},
		CommonName: defaultClientCommonName,
	}
	clientCert, clientKey, err := CreateCertPEM(clientOpts, kpa)
	if err != nil {
		return nil, err
	}

	return &Certs{
		Kpa:        kpa,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}, nil
}

func addPrefix(prefix, filename string) string {
	if len(prefix) == 0 {
		prefix = defaultPrefix
	}
	return fmt.Sprintf("%s_%s", prefix, filename)
}
