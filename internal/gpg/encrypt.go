package gpg

import (
	"bytes"
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// EncryptString encrypts plaintext to the recipient(s) in publicKeyPath.
// The output is binary OpenPGP data suitable for writing to a *.gpg shard file.
func EncryptString(plaintext string, publicKeyPath string) ([]byte, error) {
	f, err := os.Open(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("open public key %q: %w", publicKeyPath, err)
	}
	defer f.Close()

	entities, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("read armored public key %q: %w", publicKeyPath, err)
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("no entities found in public key %q", publicKeyPath)
	}

	var buf bytes.Buffer
	// openpgp.Encrypt returns a WriteCloser for the plaintext payload.
	wc, err := openpgp.Encrypt(&buf, entities, nil, nil, &packet.Config{})
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if _, err := wc.Write([]byte(plaintext)); err != nil {
		_ = wc.Close()
		return nil, fmt.Errorf("encrypt write payload: %w", err)
	}
	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("encrypt close: %w", err)
	}
	return buf.Bytes(), nil
}

