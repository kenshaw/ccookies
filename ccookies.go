// Package ccookies provides a quick way to decode cookies from chromium based
// browsers.
//
// Some functions cribbed from kooky.
package ccookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	sservice "github.com/zalando/go-keyring/secret_service"
	"golang.org/x/crypto/pbkdf2"
)

/*
vivaldi 88.0.4324.99 sqlite_master:
CREATE TABLE cookies(
	creation_utc INTEGER NOT NULL,
	host_key TEXT NOT NULL,
	name TEXT NOT NULL,
	value TEXT NOT NULL,
	path TEXT NOT NULL,
	expires_utc INTEGER NOT NULL,
	is_secure INTEGER NOT NULL,
	is_httponly INTEGER NOT NULL,
	last_access_utc INTEGER NOT NULL,
	has_expires INTEGER NOT NULL DEFAULT 1,
	is_persistent INTEGER NOT NULL DEFAULT 1,
	priority INTEGER NOT NULL DEFAULT 1,
	encrypted_value BLOB DEFAULT '',
	samesite INTEGER NOT NULL DEFAULT -1,
	source_scheme INTEGER NOT NULL DEFAULT 0,
	source_port INTEGER NOT NULL DEFAULT -1,
	is_same_party INTEGER NOT NULL DEFAULT 0,
	UNIQUE (host_key, name, path)
)
*/

// Read reads the cookies from the provided sqlite3 file on disk.
func Read(file, host string) ([]*http.Cookie, error) {
	driver := driverName()
	if driver == "" {
		return nil, errors.New("code using ccookies must import a sqlite driver!")
	}
	db, err := sql.Open(driver, file)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// build sql
	var args []interface{}
	// sqlstr := `SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite FROM cookies`
	sqlstr := `SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies`
	if host != "" {
		sqlstr += " WHERE host_key LIKE ?"
		args = append(args, "%"+host)
	}
	rows, err := db.Query(sqlstr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cookies []*http.Cookie
	for rows.Next() {
		// cookie fields
		var hostKey string
		var name string
		var encryptedValue EncryptedValue
		var path string
		var expiresUTC ExpiresUTC
		var isSecure bool
		var isHTTPOnly bool
		// var sameSite http.SameSite
		if err := rows.Scan(
			&hostKey,
			&name,
			&encryptedValue,
			&path,
			&expiresUTC,
			&isSecure,
			&isHTTPOnly,
			//&sameSite,
		); err != nil {
			return nil, err
		}
		cookies = append(cookies, &http.Cookie{
			Name:     name,
			Value:    encryptedValue.String(),
			Path:     path,
			Domain:   hostKey,
			Expires:  expiresUTC.Time(),
			Secure:   isSecure,
			HttpOnly: isHTTPOnly,
			// SameSite: sameSite,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cookies, nil
}

// driverName returns the first sqlite3 driver name it encounters.
func driverName() string {
	for _, n := range sql.Drivers() {
		switch n {
		case "sqlite3", "sqlite":
			return n
		}
	}
	return ""
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
	return []byte(v)
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
