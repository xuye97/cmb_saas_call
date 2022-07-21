package cmb_saas_call

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	goaes "github.com/rosbit/go-aes"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"github.com/xuyien97/cmb_saas_call/util"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type CmbConf struct {
	ServiceURL            string //招行服务器地址
	RSAUserPrivateKey     string //用户私钥
	SM2UserPrivateKey     string //国密SM2用户私钥
	RSAPlatformPrivateKey string //平台私钥
	SM2PlatformPrivateKey string //国密SM2平台私钥
	AesKey                string //AES密钥
	SM4Key                string //SM4对称密钥
	RSABankPublicKey      string //银行RSA公钥
	SM2BankPublicKey      string //银行SM2公钥
	Insplat               string //平台代码
	UID                   string //操作人id(调用的时候传过来)
	ALG                   string //是不是采用国密算法（值为SM的时候代表使用国密算法）
	bankPubKey            *rsa.PublicKey
	userPrivateKey        *rsa.PrivateKey
	platformPrivateKey    *rsa.PrivateKey
	userSM2PrivateKey     *sm2.PrivateKey
	platformSM2PrivateKey *sm2.PrivateKey
	bankSM2PubKey         *sm2.PublicKey
}

type Signature struct {
	Sigdat string `json:"sigdat"` //sigdat先预填充"__signature_sigdat__"
	Sigtim string `json:"sigtim"` //sigtim为当前时间（年月日时分秒，24小时制）20210818165457
}
type Signature2 struct {
	Sigdat     string `json:"sigdat"`     //sigdat先预填充"__signature_sigdat__"
	Sigtim     string `json:"sigtim"`     //sigtim为当前时间（年月日时分秒，24小时制）20210818165457
	Paltsigdat string `json:"paltsigdat"` //平台签名 必须在Signature 的最后面
}

func (cmbConf *CmbConf) parsePrivateKey() error {
	if cmbConf.ALG != "SM" && cmbConf.userPrivateKey == nil && cmbConf.RSAUserPrivateKey != "" {
		pk, err := util.ParsePrivateKeyContent(cmbConf.RSAUserPrivateKey, "PKCS1")
		if err != nil {
			return err
		}
		cmbConf.userPrivateKey = pk
	}
	if cmbConf.ALG == "SM" && cmbConf.userSM2PrivateKey == nil && cmbConf.SM2UserPrivateKey != "" {
		decodeBytes, err := base64.StdEncoding.DecodeString(cmbConf.SM2UserPrivateKey)
		if err != nil {
			return err
		}
		hexStr := hex.EncodeToString(decodeBytes)
		pk, err := x509.ReadPrivateKeyFromHex(hexStr)
		cmbConf.userSM2PrivateKey = pk
	}
	//平台私钥永远是sm2
	if cmbConf.platformSM2PrivateKey == nil && cmbConf.SM2PlatformPrivateKey != "" {
		decodeBytes, err := base64.StdEncoding.DecodeString(cmbConf.SM2PlatformPrivateKey)
		if err != nil {
			return err
		}
		hexStr := hex.EncodeToString(decodeBytes)
		pk, err := x509.ReadPrivateKeyFromHex(hexStr)
		cmbConf.platformSM2PrivateKey = pk
	}
	return nil
}
func (cmbConf *CmbConf) parseBankPublicKey() error {
	if cmbConf.ALG == "SM" {
		if cmbConf.bankSM2PubKey == nil && cmbConf.SM2BankPublicKey != "" {
			decodeBytes, err := base64.StdEncoding.DecodeString(cmbConf.SM2BankPublicKey)
			if err != nil {
				return err
			}
			pk, err := x509.ReadPublicKeyFromHex(hex.EncodeToString(decodeBytes))
			cmbConf.bankSM2PubKey = pk
		}
	} else {
		if cmbConf.bankPubKey == nil && cmbConf.RSABankPublicKey != "" {
			pk, err := util.ParsePublicKeyContent(cmbConf.RSABankPublicKey)
			if err != nil {
				return err
			}
			cmbConf.bankPubKey = pk
		}
	}
	return nil
}

// MakeSignature 签名方法
//RSA存量用户加签加密逻辑为：使用用户RSA私钥签名->平台方SM私钥再签名->用户的AES密钥加密；
//新用户加签加密逻辑为：使用用户SM私钥签名->平台方SM私钥再签名->用户的对称（SM4）密钥加密；
func (cmbConf *CmbConf) MakeSignature(body map[string]interface{}) (string, error) {
	if err := cmbConf.parsePrivateKey(); err != nil {
		return "", err
	}
	// 增加时间戳
	now := time.Now()
	ts := now.Format("20060102150405")
	//用于生成用户签名
	body["signature"] = &Signature{
		Sigtim: ts,
		Sigdat: "__signature_sigdat__",
	}
	bToSign, _ := json.Marshal(body)
	var err error
	var signature, paltSigdat []byte
	if cmbConf.ALG == "SM" {
		//国密sm2算法签名
		signature, err = util.SM2Encrypt(cmbConf.userSM2PrivateKey, bToSign, cmbConf.getIDIV())
		if err != nil {
			return "", err
		}
	} else {
		bSha := sha256.Sum256(bToSign)
		signature, err = rsa.SignPKCS1v15(rand.Reader, cmbConf.userPrivateKey, crypto.SHA256, bSha[:])
		if err != nil {
			return "", err
		}
	}
	//生成平台签名
	paltSigdat, err = util.SM2Encrypt(cmbConf.platformSM2PrivateKey, []byte(base64.StdEncoding.EncodeToString(signature)), cmbConf.getIDIV())
	if err != nil {
		return "", err
	}
	body["signature"] = Signature2{
		Sigtim:     ts,
		Sigdat:     base64.StdEncoding.EncodeToString(signature),
		Paltsigdat: base64.StdEncoding.EncodeToString(paltSigdat),
	}
	bToSign, _ = json.Marshal(body)
	var res []byte
	if cmbConf.ALG == "SM" {
		//SM4对称密钥加密
		sm4.SetIV(cmbConf.getIDIV())
		res, err = sm4.Sm4Cbc([]byte(cmbConf.SM4Key), bToSign, true)
		if err != nil {
			return "", err
		}
	} else {
		//最后对所有的数据进行AES加密 加密方式 ECB 补码方式 PKCS7
		res, err = goaes.AesEncryptECB(bToSign, []byte(cmbConf.AesKey))
		if err != nil {
			return "", err
		}
	}
	return base64.StdEncoding.EncodeToString(res), nil
}

func (cmbConf *CmbConf) ParseResponse(cipher string) (decryptedBody []byte, body map[string]interface{}, err error) {
	if err = cmbConf.parseBankPublicKey(); err != nil {
		return
	}

	res, e := base64.StdEncoding.DecodeString(cipher)
	if e != nil {
		err = e
		return
	}
	var bToSign []byte
	if cmbConf.ALG == "SM" {
		//国密
		sm4.SetIV(cmbConf.getIDIV())
		bToSign, e = sm4.Sm4Cbc([]byte(cmbConf.SM4Key), res, false)
	} else {
		//密钥
		bToSign, e = goaes.AesDecryptECB(res, []byte(cmbConf.AesKey))
	}
	if e != nil {
		err = e
		return
	}
	decryptedBody = bToSign
	if err = json.Unmarshal(bToSign, &body); err != nil {
		return
	}
	signStruct, ok := body["signature"]
	if !ok || signStruct == nil {
		err = errors.New(fmt.Sprintf("item signature not found"))
		return
	}
	var sigtim, sigdat string
	switch signStruct.(type) {
	case map[string]interface{}:
		ss := signStruct.(map[string]interface{})
		sigtimI, ok := ss["sigtim"]
		if !ok {
			err = errors.New(fmt.Sprintf("signature/sigtim not found"))
			return
		}
		sigtim, ok = sigtimI.(string)
		if !ok {
			err = errors.New(fmt.Sprintf("string type of signature/sigtim expected"))
			return
		}
		sigdatI, ok := ss["sigdat"]
		if !ok {
			err = errors.New(fmt.Sprintf("signature/sigdat not found"))
			return
		}
		sigdat, ok = sigdatI.(string)
		if !ok {
			err = errors.New(fmt.Sprintf("string type of signature/sigdat expected"))
			return
		}
	default:
		err = errors.New(fmt.Sprintf("bad type for item signature"))
		return
	}

	signature, e := base64.StdEncoding.DecodeString(sigdat)
	if e != nil {
		err = e
		return
	}

	body["signature"] = map[string]interface{}{
		"sigtim": sigtim,
		"sigdat": "__signature_sigdat__",
	}
	bToSign, _ = json.Marshal(body)
	fmt.Printf("strToSign: %s\n", bToSign)
	if cmbConf.ALG == "SM" {
		//国密
		if cmbConf.bankSM2PubKey.Verify(bToSign, signature) {
			err = errors.New("验签失败")
			return
		}
	} else {
		bSha := sha256.Sum256(bToSign)
		if err = rsa.VerifyPKCS1v15(cmbConf.bankPubKey, crypto.SHA256, bSha[:], signature); err != nil {
			return
		}
	}
	return
}

func (cmbConf *CmbConf) getIDIV() []byte {
	userid := cmbConf.UID + "0000000000000000"
	return []byte(userid)[:16]
}

//生成请求
func (cmbConf *CmbConf) makeReq(api string, reqBodyJSON interface{}) (reqBodyStr string, err error) {
	now := time.Now()
	reqId := fmt.Sprintf("%s%s", now.Format("20060102150405.000"), api)
	reqId = reqId[:14] + reqId[15:]

	body := map[string]interface{}{
		"request": map[string]interface{}{
			"head": map[string]interface{}{
				"funcode": api,
				"userid":  cmbConf.UID,
				"reqid":   reqId,
			},
			"body": reqBodyJSON,
		},
	}
	res, e := cmbConf.MakeSignature(body)
	if e != nil {
		err = e
		return
	}
	SM := ""
	if cmbConf.ALG == "SM" {
		SM = "&ALG=SM"
	}
	reqBodyStr = fmt.Sprintf("UID=%s&FUNCODE=%s&INSPLAT=%s&DATA=%s", cmbConf.UID, api, cmbConf.Insplat+SM, url.QueryEscape(res))
	return
}

//CallCDC 发送请求
func (cmbConf *CmbConf) CallCDC(apiName string, params map[string]interface{}) (res []byte, err error) {
	body, e := cmbConf.makeReq(apiName, params)
	if e != nil {
		err = e
		return
	}
	reader := bytes.NewReader([]byte(body))
	request, e := http.NewRequest("POST", cmbConf.ServiceURL, reader)
	defer request.Body.Close()
	if e != nil {
		err = e
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{}
	resp, e := client.Do(request) //Do 方法发送请求，返回 HTTP 回复
	if e != nil {
		err = e
		return
	}
	resBody, e := ioutil.ReadAll(resp.Body)
	if e != nil {
		err = e
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = errors.New(fmt.Sprintf("status: %d, resp: %s", resp.StatusCode, string(resBody)))
		return
	}

	res, _, e = cmbConf.ParseResponse(string(resBody))
	if e != nil {
		err = e
		return
	}
	return
}
