package dnp3

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// AES-GMAC (IEEE 1815-2012 7.6.2.1.1, MAC algorithm 6): AES-GCM with no
// plaintext, a 96-bit tag and a 96-bit deterministic IV (Table 7-20)
// built from the sender's DNP3 address, the user number, a key change or
// status change sequence number and a challenge sequence number (sources
// per object in Table 7-21). The IV fields go least significant octet
// first like every DNP3 integer (F-592).

// GMACIV builds the 12-octet IV.
func GMACIV(sender, usr uint16, ksq, csq uint32) []byte {
	iv := binary.LittleEndian.AppendUint16(nil, sender)
	iv = binary.LittleEndian.AppendUint16(iv, usr)
	iv = binary.LittleEndian.AppendUint32(iv, ksq)
	return binary.LittleEndian.AppendUint32(iv, csq)
}

// GMAC is the 12-octet AES-GMAC tag of the concatenated parts.
func GMAC(key, iv []byte, parts ...[]byte) ([]byte, error) {
	if len(iv) != 12 {
		return nil, errors.New("an AES-GMAC IV is 12 octets")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-GMAC key: %w", err)
	}
	g, err := cipher.NewGCMWithTagSize(block, 12)
	if err != nil {
		return nil, err
	}
	var aad []byte
	for _, p := range parts {
		aad = append(aad, p...)
	}
	return g.Seal(nil, iv, nil, aad), nil
}

// MACIV computes the MAC of algorithm mal; iv is used by AES-GMAC only.
func MACIV(mal uint8, key, iv []byte, parts ...[]byte) ([]byte, error) {
	if mal == MACAESGMAC {
		return GMAC(key, iv, parts...)
	}
	return MAC(mal, key, parts...)
}
