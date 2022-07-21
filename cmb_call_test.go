package cmb_saas_call

import (
	"fmt"
	"testing"
)

func TestCMBCALL(t *testing.T) {
	cmbConf := &CmbConf{}
	cmbConf.ServiceURL = "http://cdctest.cmburl.cn/cdcserver/api/v2"
	cmbConf.ALG = "SM"
	cmbConf.SM2UserPrivateKey = ""
	cmbConf.SM2PlatformPrivateKey = ""
	cmbConf.SM2BankPublicKey = ""
	cmbConf.SM4Key = ""
	cmbConf.UID = ""
	cmbConf.RSAUserPrivateKey = ""
	cmbConf.AesKey = ""
	cmbConf.Insplat = ""
	res, err := cmbConf.CallCDC("DCLISMOD", map[string]interface{}{
		"buscod": "N03020",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(res))
}
