package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const verifyPlaintext = "mnemox-vault-check"

type CryptoConfig struct {
	Salt    string `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

type configFile struct {
	Name      string       `json:"name"`
	CreatedAt string       `json:"created_at"`
	Crypto    CryptoConfig `json:"crypto"`
}

type cipherBox struct {
	key []byte
}

func newCryptoConfig() (CryptoConfig, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return CryptoConfig{}, err
	}
	return CryptoConfig{
		Salt:    base64.RawURLEncoding.EncodeToString(salt),
		Time:    3,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
	}, nil
}

func readPassphrase(confirm bool) (string, error) {
	if pass := os.Getenv("MNEMOX_PASSPHRASE"); pass != "" {
		return pass, nil
	}
	fmt.Print("Mnemox passphrase: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if confirm {
		fmt.Print("Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		if subtle.ConstantTimeCompare(first, second) != 1 {
			return "", errors.New("passphrases do not match")
		}
	}
	if len(first) == 0 {
		return "", errors.New("passphrase cannot be empty")
	}
	return string(first), nil
}

func newCipherBox(passphrase string, cfg CryptoConfig) (*cipherBox, error) {
	salt, err := base64.RawURLEncoding.DecodeString(cfg.Salt)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
	return &cipherBox{key: key}, nil
}

func (c *cipherBox) encryptJSON(v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return c.encrypt(plain)
}

func (c *cipherBox) decryptJSON(token []byte, v any) error {
	plain, err := c.decrypt(token)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

func (c *cipherBox) encrypt(plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}

func (c *cipherBox) decrypt(token []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, err
	}
	if len(token) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("encrypted payload is too short")
	}
	nonce := token[:chacha20poly1305.NonceSizeX]
	ciphertext := token[chacha20poly1305.NonceSizeX:]
	return aead.Open(nil, nonce, ciphertext, nil)
}
