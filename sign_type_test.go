package alipay

import (
	"crypto"
	"testing"
)

func TestNormalizeSignType(t *testing.T) {
	st, h, err := normalizeSignType("")
	if err != nil || st != kSignTypeRSA2 || h != crypto.SHA256 {
		t.Fatalf("empty: st=%q hash=%v err=%v", st, h, err)
	}
	st, h, err = normalizeSignType("RSA2")
	if err != nil || st != kSignTypeRSA2 || h != crypto.SHA256 {
		t.Fatalf("RSA2: st=%q hash=%v err=%v", st, h, err)
	}
	st, h, err = normalizeSignType("rsa")
	if err != nil || st != kSignTypeRSA || h != crypto.SHA1 {
		t.Fatalf("RSA: st=%q hash=%v err=%v", st, h, err)
	}
	if _, _, err := normalizeSignType("MD5"); err == nil {
		t.Fatal("expected unsupported sign type error")
	}
}

func TestWithSignTypeOption(t *testing.T) {
	c := &Client{}
	WithSignType("RSA")(c)
	if c.signType != "RSA" {
		t.Fatalf("got %q", c.signType)
	}
	if c.getSignHash() != crypto.SHA1 {
		t.Fatalf("hash=%v", c.getSignHash())
	}
	WithSignType("RSA2")(c)
	if c.getSignType() != kSignTypeRSA2 || c.getSignHash() != crypto.SHA256 {
		t.Fatalf("RSA2 hash mismatch")
	}
}
