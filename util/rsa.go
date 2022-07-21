package util

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	pri_key_begin = "-----BEGIN RSA PRIVATE KEY-----"
	pri_key_end   = "-----END RSA PRIVATE KEY-----"

	pub_key_begin = "-----BEGIN CERTIFICATE-----"
	pub_key_end   = "-----END CERTIFICATE-----"
)

func parsePrivateKey(b []byte, typ string) (pri *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(b)
	if block == nil {
		err = errors.New(fmt.Sprintf("failed to parse private key"))
		return
	}

	switch typ {
	case "PKCS1":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PKCS8":
		prkI, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			err = e
			return
		}
		pri = prkI.(*rsa.PrivateKey)
		return
	default:
		err = errors.New(fmt.Sprintf("unknow type %s", typ))
		return
	}
}

func ParsePrivateKeyContent(priKey string, typ string) (pri *rsa.PrivateKey, err error) {
	hasMark := true
	b := &bytes.Buffer{}
	if !strings.HasPrefix(priKey, pri_key_begin) {
		hasMark = false
		b.WriteString(pri_key_begin)
		b.WriteRune('\n')
	}
	b.WriteString(priKey)
	b.WriteRune('\n')
	if !hasMark {
		b.WriteString(pri_key_end)
		b.WriteRune('\n')
	}

	return parsePrivateKey(b.Bytes(), typ)
}

func parsePublicKey(b []byte) (pub *rsa.PublicKey, err error) {
	block, _ := pem.Decode(b)
	if block == nil {
		err = errors.New(fmt.Sprintf("failed to parse public key"))
		return
	}

	pubInterface, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		err = e
		return
	}
	if pub, ok := pubInterface.(*rsa.PublicKey); !ok {
		return nil, errors.New(fmt.Sprintf("unknown format"))
	} else {
		return pub, nil
	}
}

func ParsePublicKeyContent(pubKey string) (pub *rsa.PublicKey, err error) {
	hasMark := true
	b := &bytes.Buffer{}
	if !strings.HasPrefix(pubKey, pub_key_begin) {
		hasMark = false
		b.WriteString(pub_key_begin)
		b.WriteRune('\n')
	}
	b.WriteString(pubKey)
	b.WriteRune('\n')
	if !hasMark {
		b.WriteString(pub_key_end)
		b.WriteRune('\n')
	}

	return parsePublicKey(b.Bytes())
}
