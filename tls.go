package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// GetServerCertificateFunc returns a function for tls.Config.GetCertificate
func GetServerCertificateFunc(certFile, keyFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return LoadKeyPair(certFile, keyFile)
	}
}

// GetConfigForClientFunc returns a function for tls.Config.GetConfigForClient
func GetConfigForClientFunc(certFile, keyFile, caCertFile string) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) {
		certificates, err := LoadCAFile(caCertFile)
		if err != nil {
			return nil, err
		}

		tlsConfig := tls.Config{
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      certificates,
			GetCertificate: GetServerCertificateFunc(certFile, keyFile),
		}
		return &tlsConfig, nil
	}
}

// LoadKeyPair reads and parses a public/private key pair from a pair of files.
// The files must contain PEM encoded data.
func LoadKeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// LoadCAFile reads and parses CA certificates from a file into a pool.
// The file must contain PEM encoded data.
func LoadCAFile(caFile string) (*x509.CertPool, error) {
	pemCerts, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemCerts)
	return pool, nil
}
