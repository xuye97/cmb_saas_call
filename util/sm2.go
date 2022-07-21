package util

import (
	"bytes"
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"
)

func SM2Encrypt(privateKey *sm2.PrivateKey, msg, uid []byte) ([]byte, error) {
	r, s, err := sm2.Sm2Sign(privateKey, msg, uid, rand.Reader)
	if err != nil {
		panic(err)
	}
	res := make([]byte, 0)
	var buffer bytes.Buffer
	buffer.Write(r.Bytes())
	res = append(res, buffer.Bytes()[:32]...)
	var buffer2 bytes.Buffer
	buffer2.Write(s.Bytes())
	res = append(res, buffer2.Bytes()[0:32]...)
	return res, nil
}
