package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"strconv"
	"time"

	sservice "github.com/zalando/go-keyring/secret_service"
	"golang.org/x/crypto/pbkdf2"
)

// ExpiresUTC wraps a UTC based expiry time.
type ExpiresUTC time.Time

// Time returns the value as a standard time.
func (v ExpiresUTC) Time() time.Time {
	return time.Time(v)
}

// Scan satisfies the sql.Scanner interface.
func (v *ExpiresUTC) Scan(z interface{}) error {
	var i int64
	switch x := z.(type) {
	case int64:
		i = x
	case []byte:
		var err error
		if i, err = strconv.ParseInt(string(x), 10, 64); err != nil {
			return err
		}
	case string:
		var err error
		if i, err = strconv.ParseInt(x, 10, 64); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported type %T", z)
	}
	*v = ExpiresUTC(time.Unix(0, (i*10-116444736e9)*100))
	return nil
}

// EncryptedValue wraps an encrypted value.
type EncryptedValue []byte

// String satisfies the fmt.Stringer interface.
func (v EncryptedValue) String() string {
	return string(v)
}

// Bytes returns the encrypted value as bytes.
func (v EncryptedValue) Bytes() []byte {
	return v
}

// Scan satisfies the sql.Scanner interface.
func (v *EncryptedValue) Scan(z interface{}) error {
	buf, ok := z.([]byte)
	if !ok {
		return fmt.Errorf("unsupported type %T", z)
	}
	if len(buf) <= 3 {
		return fmt.Errorf("length %d <= 3", len(buf))
	}
	ver := string(buf[0:3])
	var secret []byte
	switch {
	case ver == "v11":
		var err error
		secret, err = appSecret("chrome")
		if err != nil {
			return err
		}
	default:
		secret = []byte("peanuts")
	}
	var err error
	*v, err = aesDecrypt(buf[3:], secret)
	return err
}

// aesDecrypt decrypts the encrypted bytes using specified secret.
func aesDecrypt(enc, secret []byte) ([]byte, error) {
	if len(enc)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("length % %d != 0", aes.BlockSize)
	}
	salt, iv, iterations := aesConfig()
	block, err := aes.NewCipher(
		pbkdf2.Key(secret, salt, iterations, aes.BlockSize, sha1.New),
	)
	if err != nil {
		return nil, err
	}
	dec := make([]byte, len(enc))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, enc)
	// chop padding
	padding := int(dec[len(dec)-1])
	if padding > 16 {
		return nil, fmt.Errorf("invalid padding: %d", padding)
	}
	return dec[:len(dec)-padding], nil
}

// aesConfig returns the salt, iv, and iterations for aes decryption.
func aesConfig() ([]byte, []byte, int) {
	return []byte(`saltysalt`), []byte(`                `), 1
}

// appSecret reads the specified app secret from the system's keyring.
func appSecret(app string) ([]byte, error) {
	svc, err := sservice.NewSecretService()
	if err != nil {
		return nil, err
	}
	collection := svc.GetLoginCollection()
	if err := svc.Unlock(collection.Path()); err != nil {
		return nil, err
	}
	res, err := svc.SearchItems(collection, map[string]string{
		"application": app,
	})
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("application %q secret not found in keyring", app)
	}
	// open a session
	sess, err := svc.OpenSession()
	if err != nil {
		return nil, err
	}
	defer svc.Close(sess)
	secret, err := svc.GetSecret(res[0], sess.Path())
	if err != nil {
		return nil, err
	}
	return secret.Value, nil
}
