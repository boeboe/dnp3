package dnp3_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cB-Sigma/dnp3"
)

// Covers: SIG-IPE-642
func TestDNP3AttributeCodec(t *testing.T) {
	var b []byte
	b = dnp3.AppendAttribute(b, 247, 0, "feeder")
	b = dnp3.AppendAttribute(b, 241, 0, 2048.0)
	b = dnp3.AppendAttribute(b, 217, 0, -5.0)
	b = dnp3.AppendAttribute(b, 218, 0, 1.5)
	// A two-octet signed integer and a four-octet float, hand-built.
	b = append(b, 0, 211, dnp3.Q8StartStop, 0, 0, dnp3.AttrINT, 2, 0xFE, 0xFF)
	b = append(b, 0, 212, dnp3.Q8StartStop, 0, 0, dnp3.AttrFLT, 4, 0x00, 0x00, 0xC0, 0x3F)
	blocks, err := dnp3.ParseObjects(b, true)
	if err != nil {
		t.Fatal(err)
	}
	var got []any
	for _, blk := range blocks {
		got = append(got, blk.Points[0].Value)
	}
	want := []any{"feeder", 2048.0, -5.0, 1.5, -2.0, 1.5}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("attributes = %v, want %v", got, want)
	}
	if dnp3.AttributeName(247) != "device-name" || dnp3.AttributeName(7) != "attribute-7" {
		t.Error("attribute names")
	}
	if _, err := dnp3.ParseObjects([]byte{0, 247, 0, 0, 0, 1, 10, 'a'}, true); err == nil {
		t.Error("a truncated attribute decoded")
	}
	if _, err := dnp3.ParseObjects([]byte{0, 211, 0, 0, 0, dnp3.AttrINT, 5, 1, 2, 3, 4, 5}, true); err == nil {
		t.Error("a five-octet integer attribute decoded")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3394 section 4 vectors (4.1, 4.3, 4.6), RFC 4231 test case 2
// (HMAC-SHA-256) and RFC 2202 test case 2 (HMAC-SHA-1) truncated as each
// MAC algorithm code says, and group 120 object framing.
//
// Covers: SIG-IPE-645
func TestDNP3AuthPrimitives(t *testing.T) {
	kek256 := "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
	for _, tc := range []struct{ name, kek, key, wrapped string }{
		{"4.1", "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		{"4.3", kek256, "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"4.6", kek256, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	} {
		kek, key, want := mustHex(t, tc.kek), mustHex(t, tc.key), mustHex(t, tc.wrapped)
		got, err := dnp3.WrapKey(kek, key)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: wrap = %X %v", tc.name, got, err)
		}
		if back, err := dnp3.UnwrapKey(kek, want); err != nil || !bytes.Equal(back, key) {
			t.Errorf("%s: unwrap = %X %v", tc.name, back, err)
		}
		bad := bytes.Clone(want)
		bad[len(bad)-1] ^= 1
		if _, err := dnp3.UnwrapKey(kek, bad); err == nil {
			t.Errorf("%s: a changed wrapped key unwrapped", tc.name)
		}
	}
	data := []byte("what do ya want for nothing?")
	sha256Full := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	sha1Full := "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
	for _, tc := range []struct {
		mal  uint8
		want string
	}{
		{dnp3.MACSHA256Trunc16, sha256Full[:32]}, {dnp3.MACSHA256Trunc8, sha256Full[:16]},
		{dnp3.MACSHA1Trunc10, sha1Full[:20]}, {dnp3.MACSHA1Trunc8, sha1Full[:16]},
	} {
		// The MAC input may come in parts.
		got, err := dnp3.MAC(tc.mal, []byte("Jefe"), data[:10], data[10:])
		if err != nil || hex.EncodeToString(got) != tc.want {
			t.Errorf("MAC %d = %x %v, want %s", tc.mal, got, err, tc.want)
		}
	}
	if _, err := dnp3.MAC(6, []byte("k"), data); err == nil {
		t.Error("an unsupported MAC algorithm computed")
	}
	// Group 120 framing: free-format objects and the key status request.
	obj := dnp3.AppendAuthObject(nil, dnp3.AuthReply, []byte{1, 2, 3})
	if !bytes.Equal(obj, []byte{120, 2, 0x5B, 1, 3, 0, 1, 2, 3}) {
		t.Errorf("g120v2 = % X", obj)
	}
	if v, d, err := dnp3.ParseAuthObject(obj); v != 2 || !bytes.Equal(d, []byte{1, 2, 3}) || err != nil {
		t.Errorf("parse g120v2 = %d % X %v", v, d, err)
	}
	if obj := dnp3.AppendAuthObject(nil, dnp3.AuthKeyStatusReq, []byte{1, 0}); !bytes.Equal(obj, []byte{120, 4, 0x07, 1, 1, 0}) {
		t.Errorf("g120v4 = % X", obj)
	}
	ks := dnp3.KeyStatus{KSQ: 7, User: 1, KeyWrap: 2, Status: 1, MAL: 4, Challenge: []byte{9, 9, 9, 9}, MAC: []byte{5, 5}}
	if back, err := dnp3.ParseKeyStatus(dnp3.AppendKeyStatus(nil, ks)); err != nil || fmt.Sprint(back) != fmt.Sprint(ks) {
		t.Errorf("key status round trip = %+v %v", back, err)
	}
	ctrl, mon := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	plain := dnp3.SessionKeyData(ctrl, mon, []byte{7, 7, 7})
	if len(plain)%8 != 0 {
		t.Errorf("key data of %d octets is not padded", len(plain))
	}
	if c, m, rest, err := dnp3.ParseSessionKeyData(plain); err != nil || !bytes.Equal(c, ctrl) || !bytes.Equal(m, mon) || !bytes.HasPrefix(rest, []byte{7, 7, 7}) {
		t.Errorf("key data parse: %v", err)
	}
	for _, bad := range [][]byte{{120, 1, 0x5B, 1, 9, 0, 1}, {120, 1, 0x17, 1}, {60, 1, 6, 0}} {
		if _, _, err := dnp3.ParseAuthObject(bad); err == nil {
			t.Errorf("% X parsed", bad)
		}
	}
}

const updateKeyHex = "00112233445566778899aabbccddeeff"

// hexKey decodes a hex key of the tests.
func hexKey(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}
