package gpg

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// DecryptString decrypts a binary OpenPGP message (the *.gpg shard) using
// the private key in privateKeyPath.
//
// If the key is passphrase protected, passphrase must be the correct value.
func DecryptString(shardPath string, privateKeyPath string, passphrase string) (string, error) {
	shardBytes, err := os.ReadFile(shardPath)
	if err != nil {
		return "", fmt.Errorf("read shard %q: %w", shardPath, err)
	}

	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read private key %q: %w", privateKeyPath, err)
	}

	// ReadMessage expects a KeyRing. The simplest approach is to parse whatever
	// format we have (armored or binary) as a key ring.
	var keyRing openpgp.EntityList
	{
		// Try armored first.
		if entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyBytes)); err == nil && len(entities) > 0 {
			keyRing = entities
		} else {
			// Fall back to binary key ring.
			entities, err2 := openpgp.ReadKeyRing(bytes.NewReader(keyBytes))
			if err2 != nil {
				return "", fmt.Errorf("parse private key %q: %w", privateKeyPath, err2)
			}
			keyRing = entities
		}
	}
	if len(keyRing) == 0 {
		return "", fmt.Errorf("no entities found in private key %q", privateKeyPath)
	}

	// Decrypt the message; if the private key is encrypted, the prompt callback
	// provides the passphrase.
	md, err := openpgp.ReadMessage(
		bytes.NewReader(shardBytes),
		keyRing,
		func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			// The operator is responsible for providing the correct passphrase.
			return []byte(passphrase), nil
		},
		nil,
	)
	if err != nil {
		if passphrase == "" {
			return "", fmt.Errorf("decrypt shard %q: %w (tip: provide --passphrase if your key is protected)", shardPath, err)
		}
		return "", fmt.Errorf("decrypt shard %q: %w", shardPath, err)
	}

	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("read decrypted payload: %w", err)
	}
	return string(body), nil
}

