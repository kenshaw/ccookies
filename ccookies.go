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
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/kenshaw/ccookies/models"
	"golang.org/x/net/publicsuffix"
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

// ReadContext reads the cookies from the provided sqlite3 file on disk.
func ReadContext(ctx context.Context, file, host string) ([]*http.Cookie, error) {
	// check sqlite driver
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
	// query func and params
	f := models.Cookies
	if host != "" {
		f, host = models.CookiesLikeHost, "%"+strings.TrimPrefix(host, "%")
	}
	// exec and convert
	res, err := f(ctx, db, host)
	if err != nil {
		return nil, err
	}
	return models.Convert(res), nil
}

// Read reads the cookies from the provided sqlite3 file on disk.
func Read(file, host string) ([]*http.Cookie, error) {
	return ReadContext(context.Background(), file, host)
}

// Jar builds a cookie jar for the url from provided cookies.
func Jar(u *url.URL, cookies ...*http.Cookie) (http.CookieJar, error) {
	// build jar
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	jar.SetCookies(u, cookies)
	return jar, nil
}

// ReadJar reads the cookies from the provided sqlite3 file for the provided
// url into a cookie jar usable with http.Client.
func ReadJar(file, urlstr string) (http.CookieJar, error) {
	// read cookies
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https" {
		return nil, fmt.Errorf("invalid url scheme %q", u.Scheme)
	}
	cookies, err := Read(file, u.Host)
	if err != nil {
		return nil, err
	}
	return Jar(u, cookies...)
}

// ReadJarFiltered reads the cookies from the provided sqlite3 file for the
// provided url into a cookie jar (usable with http.Client) consisting of of
// cookies passed through filter func f.
func ReadJarFiltered(file, urlstr string, f func(*http.Cookie) bool) (http.CookieJar, error) {
	// read cookies
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https" {
		return nil, fmt.Errorf("invalid url scheme %q", u.Scheme)
	}
	cookies, err := Read(file, u.Host)
	if err != nil {
		return nil, err
	}
	// filter
	var c []*http.Cookie
	for _, cookie := range cookies {
		if f(cookie) {
			c = append(c, cookie)
		}
	}
	return Jar(u, c...)
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
