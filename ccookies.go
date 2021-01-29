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
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
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
	db, err := sql.Open("sqlite3", file)
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
		var expiresUTC ChromeTime
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

type EncryptedValue []byte

// String satisfies the fmt.Stringer interface.
func (v EncryptedValue) String() string {
	return string(v)
}

func (v *EncryptedValue) Scan(z interface{}) error {
	buf, ok := z.([]byte)
	if !ok {
		return fmt.Errorf("encrypted value unable to scan type %T", z)
	}
	if len(buf) <= 3 {
		return fmt.Errorf("encrypted value has length %d (must be longer than 3)", len(buf))
	}
	typ := string(buf[0:3])
	var password []byte
	switch {
	case typ == "v11":
		var err error
		password, err = readAppSecret("chrome")
		if err != nil {
			return err
		}
	default:
		log.Printf("fuck")
		password = []byte("peanuts")
	}
	var err error
	*v, err = decryptAESCBC(buf, password, aescbcIterationsLinux)
	return err
}

// ChromeTime wraps a chrome time.
type ChromeTime int64

func (v ChromeTime) Time() time.Time {
	i := int64(v) * 10
	i -= 116444736e9
	return time.Unix(0, i*100)
}

func decryptAESCBC(encrypted, password []byte, iterations int) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, errors.New("empty encrypted value")
	}
	if len(encrypted) <= 3 {
		return nil, fmt.Errorf("too short encrypted value (%d<=3)", len(encrypted))
	}
	// strip "v##"
	encrypted = encrypted[3:]
	key := pbkdf2.Key(password, []byte(aescbcSalt), iterations, aescbcLength, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(encrypted))
	cbc := cipher.NewCBCDecrypter(block, []byte(aescbcIV))
	cbc.CryptBlocks(decrypted, encrypted)
	// In the padding scheme the last <padding length> bytes
	// have a value equal to the padding length, always in (1,16]
	if len(decrypted)%aescbcLength != 0 {
		return nil, fmt.Errorf("decrypted data block length is not a multiple of %d", aescbcLength)
	}
	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen > 16 {
		return nil, fmt.Errorf("invalid last block padding length: %d", paddingLen)
	}
	return decrypted[:len(decrypted)-paddingLen], nil
}

const (
	aescbcSalt            = `saltysalt`
	aescbcIV              = `                `
	aescbcIterationsLinux = 1
	// aescbcIterationsMacOS = 1003
	aescbcLength = 16
)

func readAppSecret(app string) ([]byte, error) {
	svc, err := sservice.NewSecretService()
	if err != nil {
		return nil, err
	}
	collection := svc.GetLoginCollection()
	if err := svc.Unlock(collection.Path()); err != nil {
		return nil, err
	}
	results, err := svc.SearchItems(collection, map[string]string{
		"application": app,
	})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("application %q secret not found in keyring", app)
	}
	item := results[0]
	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return nil, err
	}
	defer svc.Close(session)
	secret, err := svc.GetSecret(item, session.Path())
	if err != nil {
		return nil, err
	}
	return secret.Value, nil
}
