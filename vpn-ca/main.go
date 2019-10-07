package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type caInfo struct {
	caDir  string
	caKey  ed25519.PrivateKey
	caCert *x509.Certificate
}

func getCa(caDir string) *caInfo {
	keyFile := filepath.Join(caDir, "ca.key")
	certFile := filepath.Join(caDir, "ca.crt")
	key := readKey(keyFile)
	cert := readCert(certFile)

	return &caInfo{caDir, key, cert}
}

func readPem(pemFile, pemType string) []byte {
	pemData, _ := ioutil.ReadFile(pemFile)
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalf("unable to decode PEM")
	}
	if block.Type != pemType {
		log.Fatalf("incorrect PEM type, expected '%s'", pemType)
	}

	return block.Bytes
}

func writePem(pemFile string, derBytes []byte, pemType string) {
	file, err := os.OpenFile(pemFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	fatalIfErr(err, "unable to open file to write key")
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  pemType,
		Bytes: derBytes,
	})
	fatalIfErr(err, "unable to convert to PEM")
}

func readKey(pemFile string) ed25519.PrivateKey {
	derBytes := readPem(pemFile, "PRIVATE KEY")
	privKey, err := x509.ParsePKCS8PrivateKey(derBytes)
	fatalIfErr(err, "unable to parse private key")

	return privKey.(ed25519.PrivateKey)
}

func readCert(pemFile string) *x509.Certificate {
	derBytes := readPem(pemFile, "CERTIFICATE")
	cert, err := x509.ParseCertificate(derBytes)
	fatalIfErr(err, "unable to parse cert")

	return cert
}

func initCa(caDir string) {
	keyFile := filepath.Join(caDir, "ca.key")
	certFile := filepath.Join(caDir, "ca.crt")
	pubKey, privKey := generateKey(keyFile)
	makeRootCert(pubKey, privKey, certFile)
}

func generateKey(filename string) (ed25519.PublicKey, ed25519.PrivateKey) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(err, "unable to generate key")
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	fatalIfErr(err, "unable to convert key to DER")
	writePem(filename, der, "PRIVATE KEY")

	return pubKey, privKey
}

func makeRootCert(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, filename string) (*x509.Certificate, error) {
	tpl := getCaTemplate()
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pubKey, privKey)
	fatalIfErr(err, "unable to generate DER")
	writePem(filename, der, "CERTIFICATE")

	return x509.ParseCertificate(der)
}

func validateCommonName(commonName string) {
	validCommonName := regexp.MustCompile(`^[a-zA-Z0-9-.]+$`)
	if !validCommonName.MatchString(commonName) {
		log.Fatalf("invalid 'commonName' specified")
	}
}

func getCaTemplate() *x509.Certificate {
	// 5 years
	tpl := getTemplate("VPN CA", time.Now().AddDate(5, 0, 0), x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	tpl.IsCA = true
	tpl.MaxPathLenZero = true

	return tpl
}

func getClientTemplate(commonName string, notAfter *time.Time) *x509.Certificate {
	return getTemplate(commonName, *notAfter, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func getServerTemplate(commonName string, notAfter *time.Time) *x509.Certificate {
	// 1 year
	return getTemplate(commonName, *notAfter, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func generateSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "unable to generate serial number")

	return serialNumber
}

func getTemplate(commonName string, notAfter time.Time, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SerialNumber:          generateSerial(),
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
}

func sign(caInfo *caInfo, commonName string, tpl *x509.Certificate) *x509.Certificate {
	pubKey, _ := generateKey(filepath.Join(caInfo.caDir, fmt.Sprintf("%s.key", commonName)))
	der, err := x509.CreateCertificate(rand.Reader, tpl, caInfo.caCert, pubKey, caInfo.caKey)
	fatalIfErr(err, "unable to generate DER")

	certFile := filepath.Join(caInfo.caDir, fmt.Sprintf("%s.crt", commonName))
	writePem(certFile, der, "CERTIFICATE")

	cert, err := x509.ParseCertificate(der)
	fatalIfErr(err, "unable to parse cert")

	return cert
}

func main() {
	var caDir = flag.String("ca-dir", ".", "the CA dir")
	var caInit = flag.Bool("init", false, "initialize the CA")
	var serverCommonName = flag.String("server", "", "generate a server certificate with provided CN")
	var clientCommonName = flag.String("client", "", "generate a client certificate with provided CN")
	var notAfter = flag.String("not-after", "", "certificate is only valid until specified moment, format: 2019-08-16T14:00:00+00:00")

	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	if *caInit {
		initCa(*caDir)
		return
	}

	// XXX make sure the CA exists

	if "" == *serverCommonName && "" == *clientCommonName {
		flag.Usage()
		os.Exit(1)
	}

	caInfo := getCa(*caDir)

	if "" != *serverCommonName {
		validateCommonName(*serverCommonName)
		sign(caInfo, *serverCommonName, getServerTemplate(*serverCommonName, &caInfo.caCert.NotAfter))
		return
	}

	if "" != *clientCommonName {
		validateCommonName(*clientCommonName)
		var notAfterTime time.Time
		notAfterTime = time.Now().AddDate(0, 0, 90)
		if "" != *notAfter {
			// XXX make sure the time is actually in the future!
			p, err := time.Parse(time.RFC3339, *notAfter)
			fatalIfErr(err, "unable to parse --not-after")
			notAfterTime = p
		}

		sign(caInfo, *clientCommonName, getClientTemplate(*clientCommonName, &notAfterTime))
		return
	}
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}
