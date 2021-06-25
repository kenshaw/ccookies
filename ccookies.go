// Package ccookies provides a quick way to decode cookies from chromium based
// browsers.
//
// Some functions cribbed from kooky.
package ccookies

//go:generate ./gen.sh

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/kenshaw/ccookies/models"
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
	// check sqlite driver available
	driver := driverName()
	if driver == "" {
		return nil, errors.New("code using ccookies must import a sqlite driver!")
	}
	// open database
	db, err := sql.Open(driver, file)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// determine retrieval
	f := models.Cookies
	if host != "" {
		f, host = models.CookiesLikeHost, "%"+strings.TrimPrefix(host, "%")
	}
	// read and convert
	res, err := f(context.Background(), db, host)
	if err != nil {
		return nil, err
	}
	return models.Convert(res), nil
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
