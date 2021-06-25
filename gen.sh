#!/bin/bash

SRC=$(realpath $(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd))

SQDB=sq:$HOME/.config/vivaldi/Default/Cookies

set -x

TYPE_COMMENT='{{ . }} is a browser cookie.'
FUNC_COMMENT='{{ . }} retrieves cookies.'
FIELDS='HostKey string,Name string,EncryptedValue EncryptedValue,Path string,ExpiresUTC ExpiresUTC,IsSecure bool,IsHTTPOnly bool'
xo query $SQDB \
  --type Cookie \
  --type-comment="$TYPE_COMMENT" \
  --func Cookies \
  --func-comment="$FUNC_COMMENT" \
  --fields="$FIELDS" \
  --trim \
  --strip \
  --interpolate \
  --out=$SRC/models \
  --single=models.go \
<< 'ENDSQL'
/* %%host string,interpolate%% */
SELECT
  host_key,
  name,
  encrypted_value,
  path,
  expires_utc,
  is_secure,
  is_httponly
FROM cookies
ENDSQL

FUNC_COMMENT='{{ . }} retrieves cookies like the host.'
xo query $SQDB \
  --type Cookie \
  --func CookiesLikeHost \
  --func-comment="$FUNC_COMMENT" \
  --fields="$FIELDS" \
  --trim \
  --strip \
  --append \
  --out=$SRC/models \
  --single=models.go \
<< 'ENDSQL'
SELECT
  host_key,
  name,
  encrypted_value,
  path,
  expires_utc,
  is_secure,
  is_httponly
FROM cookies
WHERE host_key LIKE %%host string%%
ENDSQL
