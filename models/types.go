package models

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	sservice "github.com/zalando/go-keyring/secret_service"
	"golang.org/x/crypto/pbkdf2"
)

// Convert converts a slice of Cookie to http.Cookie.
func Convert(res []*Cookie) []*http.Cookie {
	var cookies []*http.Cookie
	for _, c := range res {
		cookies = append(cookies, &http.Cookie{
			Name:     c.Name,
			Value:    c.EncryptedValue.String(),
			Path:     c.Path,
			Domain:   c.HostKey,
			Expires:  c.ExpiresUTC.Time(),
			Secure:   c.IsSecure,
			HttpOnly: c.IsHTTPOnly,
			// SameSite: c.SameSite,
		})
	}
	return cookies
}

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
	switch {
	case !ok:
		return fmt.Errorf("unsupported type %T", z)
	case len(buf) == 0:
		return nil
	case len(buf) <= 3:
		return fmt.Errorf("length %d <= 3", len(buf))
	}
	// determine secret
	secret := defaultSecret
	if bytes.HasPrefix(buf, v11) {
		var err error
		if secret, err = appSecret("chrome"); err != nil {
			return err
		}
	}
	// decrypt
	var err error
	*v, err = aesDecrypt(buf[3:], secret)
	return err
}

// v11 is the v11 prefix.
var v11 = []byte("v11")

// defaultSecret is the default secret.
var defaultSecret = []byte("peanuts")

// aesDecrypt decrypts the encrypted bytes using the specified secret.
func aesDecrypt(enc, secret []byte) ([]byte, error) {
	if len(enc)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("length %% %d != 0", aes.BlockSize)
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

// appSecret returns the secret for the specified app from the secret cache or
// from the system.
func appSecret(app string) ([]byte, error) {
	systemSecrets.Lock()
	defer systemSecrets.Unlock()
	// check for cached secret
	if secret, ok := systemSecrets.secrets[app]; ok {
		return secret, nil
	}
	// read system secret
	secret, err := readSystemSecret(app)
	if err != nil {
		return nil, err
	}
	// cache
	systemSecrets.secrets[app] = secret
	return secret, nil
}

// readSystemSecret reads the secret for the specified app from the system's
// keyring.
func readSystemSecret(app string) ([]byte, error) {
	// open service and user's secrets collection
	svc, err := sservice.NewSecretService()
	if err != nil {
		return nil, err
	}
	collection := svc.GetLoginCollection()
	if err := svc.Unlock(collection.Path()); err != nil {
		return nil, err
	}
	// get app secret from collection
	res, err := svc.SearchItems(collection, map[string]string{
		"application": app,
	})
	// check secret was found
	switch {
	case err != nil:
		return nil, err
	case len(res) == 0:
		return nil, fmt.Errorf("application %q secret not found in keyring", app)
	}
	// open session
	sess, err := svc.OpenSession()
	if err != nil {
		return nil, err
	}
	defer svc.Close(sess)
	// retrieve secret
	secret, err := svc.GetSecret(res[0], sess.Path())
	if err != nil {
		return nil, err
	}
	return secret.Value, nil
}

// systemSecrets are cached system secrets.
var systemSecrets = struct {
	secrets map[string][]byte
	sync.Mutex
}{
	secrets: make(map[string][]byte),
}
