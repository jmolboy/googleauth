package googleauth

import (
	"regexp"
	"testing"
)

func TestGetCode(t *testing.T) {
	secret := RandSecret(12, RandTypeAlphaNum)

	reg := regexp.MustCompile(`([A-Z]|\d|=)+`)
	t.Log("秘钥：",secret)
	if !reg.MatchString(secret) {
		t.Error("秘钥格式错误")
	} else {
		t.Log("秘钥：", secret)
	}

	t.Log("secret:", secret)
	code, err := GetCode(secret)
	if err != nil {
		t.Error("生成code失败")
	}


	reg = regexp.MustCompile(`\d{6}`)
	if !reg.MatchString(code) {
		t.Error("code格式错误")
	} else {
		t.Log("code：", code)
	}
}
